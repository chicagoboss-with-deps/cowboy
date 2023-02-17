%% Copyright (c) 2023, Loïc Hoguin <essen@ninenines.eu>
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

-module(cowboy_http3).

-export([init/2]).

-include_lib("quicer/include/quicer.hrl").

-record(stream, {
	ref :: any(), %% @todo specs; is it useful in the record?

	%% Whether the stream is currently in a special state.
	status :: header | normal | data | discard,

	%% Stream buffer.
	buffer = <<>> :: binary(),

	%% Stream state.
	state :: {module, any()}
}).

-record(state, {
	parent :: pid(),
	conn :: any(), %% @todo specs

	%% HTTP/3 state machine.
	http3_machine :: cow_http3_machine:http3_machine(),

	%% Bidirectional streams are used for requests and responses.
	streams = #{} :: map() %% @todo specs
}).

-spec init(_, _) -> no_return().
init(Parent, Conn) ->
	Opts = #{}, %% @todo
	{ok, SettingsBin, HTTP3Machine0} = cow_http3_machine:init(server, Opts),
	{ok, Conn} = quicer:async_accept_stream(Conn, []),
	%% Immediately open a control, encoder and decoder stream.
	{ok, ControlRef} = quicer:start_stream(Conn,
		#{open_flag => ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}),
	quicer:send(ControlRef, [<<0>>, SettingsBin]),
	{ok, ControlID} = quicer:get_stream_id(ControlRef),
	{ok, EncoderRef} = quicer:start_stream(Conn,
		#{open_flag => ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}),
	quicer:send(EncoderRef, <<2>>),
	{ok, EncoderID} = quicer:get_stream_id(EncoderRef),
	{ok, DecoderRef} = quicer:start_stream(Conn,
		#{open_flag => ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}),
	quicer:send(DecoderRef, <<3>>),
	{ok, DecoderID} = quicer:get_stream_id(DecoderRef),
	%% Set the control, encoder and decoder streams in the machine.
	HTTP3Machine = cow_http3_machine:init_unidi_local_streams(
		ControlRef, ControlID, EncoderRef, EncoderID, DecoderRef, DecoderID,
		HTTP3Machine0),
	%% Quick! Let's go!
	loop(#state{parent=Parent, conn=Conn, http3_machine=HTTP3Machine}).

loop(State0=#state{conn=Conn}) ->
	receive
		%% Stream data.
		%% @todo IsFin is inside Props. But it may not be set once the data was sent.
		{quic, Data, StreamRef, Props} when is_binary(Data) ->
			logger:error("DATA ~p props ~p", [StreamRef, Props]),
			parse(State0, Data, StreamRef, Props);
		%% QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED
		{quic, new_stream, StreamRef, Flags} ->
			%% Conn does not change.
			{ok, Conn} = quicer:async_accept_stream(Conn, []),
			State = stream_new_remote(State0, StreamRef, Flags),
			loop(State);
		%% QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE
		{quic, stream_closed, StreamRef, Flags} ->
			State = stream_closed(State0, StreamRef, Flags),
			loop(State);
		%% QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE
		%%
		%% Connection closed.
		{quic, closed, Conn, _Flags} ->
			quicer:close_connection(Conn),
			%% @todo terminate here?
			ok;
		%%
		%% The following events are currently ignored either because
		%% I do not know what they do or because we do not need to
		%% take action.
		%%
		%% QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT
		{quic, transport_shutdown, Conn, _Flags} ->
			%% @todo Why isn't it BY_PEER when using curl?
			loop(State0);
		%% QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN
		{quic, peer_send_shutdown, _StreamRef, undefined} ->
			loop(State0);
		%% QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE
		{quic, send_shutdown_complete, _StreamRef, _IsGraceful} ->
			loop(State0);
		Msg ->
			logger:error("msg ~p", [Msg]),
			loop(State0)
	end.

parse(State=#state{streams=Streams}, Data, StreamRef, Props) ->
	#{StreamRef := Stream} = Streams,
	case Stream of
		#stream{buffer= <<>>} ->
			parse1(State, Data, Stream, Props);
		#stream{buffer=Buffer} ->
			parse1(State, <<Buffer/binary, Data/binary>>,
				Stream#stream{buffer= <<>>}, Props)
	end.

%% @todo Swap Data and Stream/StreamRef.
parse1(State, Data, Stream=#stream{status=header}, Props) ->
	parse_unidirectional_stream_header(State, Data, Stream, Props);
%% @todo Continuation clause for data frames.
%% @todo Clause that discards receiving data for aborted streams.
parse1(State, Data, Stream, Props) ->
	case cow_http3:parse(Data) of
		{ok, Frame, Rest} ->
			parse1(frame(State, Stream, Frame, Props), Rest, Stream, Props);
		{more, Frame, _Len} ->
			%% @todo Change state of stream to expect more data frames.
			loop(frame(State, Stream, Frame, Props));
		{ignore, Rest} ->
			parse1(ignored_frame(State, Stream), Rest, Stream, Props);
		Error = {connection_error, _, _} ->
			terminate(State, Error);
		more ->
			loop(stream_update(State, Stream#stream{buffer=Data}))
	end.

parse_unidirectional_stream_header(State0=#state{http3_machine=HTTP3Machine0},
		Data, Stream0=#stream{ref=StreamRef}, Props) ->
	case cow_http3:parse_unidi_stream_header(Data) of
		{ok, Type, Rest} when Type =:= control; Type =:= encoder; Type =:= decoder ->
			HTTP3Machine = cow_http3_machine:set_unidi_remote_stream_type(
				StreamRef, Type, HTTP3Machine0),
			State = State0#state{http3_machine=HTTP3Machine},
			Stream = Stream0#stream{status=normal},
			parse1(stream_update(State, Stream), Rest, Stream, Props);
		{ok, push, _} ->
			terminate(State0, {connection_error, h3_stream_creation_error,
				'Only servers can push. (RFC9114 6.2.2)'});
		%% Unknown stream types must be ignored. We choose to abort the
		%% stream instead of reading and discarding the incoming data.
		{undefined, _} ->
			loop(stream_abort_receive(State0, Stream0, h3_stream_creation_error))
	end.

frame(State=#state{http3_machine=HTTP3Machine0}, Stream=#stream{ref=StreamRef}, Frame, Props) ->
	#{flags := Flags} = Props,
	IsFin = case Flags band ?QUIC_RECEIVE_FLAG_FIN of
		?QUIC_RECEIVE_FLAG_FIN -> fin;
		_ -> nofin
	end,
	case cow_http3_machine:frame(Frame, IsFin, StreamRef, HTTP3Machine0) of
		{ok, HTTP3Machine} ->
			State#state{http3_machine=HTTP3Machine};
		{ok, {headers, IsFin, Headers, PseudoHeaders, BodyLen}, HTTP3Machine} ->
			headers_frame(State#state{http3_machine=HTTP3Machine},
				Stream, Headers, PseudoHeaders, BodyLen);
		{ok, {headers, IsFin, Headers, PseudoHeaders, BodyLen},
				{DecoderRef, DecData}, HTTP3Machine} ->
			%% Send the decoder data.
			quicer:send(DecoderRef, DecData),
			headers_frame(State#state{http3_machine=HTTP3Machine},
				Stream, Headers, PseudoHeaders, BodyLen)
	end.

headers_frame(State, Stream=#stream{ref=StreamRef}, Headers, PseudoHeaders, BodyLen) ->
	logger:error("~p~n~p~n~p~n~p~n~p", [State, Stream, Headers, PseudoHeaders, BodyLen]),
	{ok, StreamID} = quicer:get_stream_id(StreamRef),
	{ok, Data, EncData, _} = cow_qpack:encode_field_section([
		{<<":status">>, <<"200">>},
		{<<"content-length">>, <<"12">>},
		{<<"content-type">>, <<"text/plain">>}
	], StreamID, cow_qpack:init()),
%	%% Send the encoder data.
%	quicer:send(EncoderRef, EncData),
	%% Then the response data.
	DataLen = iolist_size(Data),
	quicer:send(StreamRef, [<<1, DataLen>>, Data]),
	quicer:send(StreamRef, <<0,12,"Hello world!">>, ?QUIC_SEND_FLAG_FIN),
%	quicer:shutdown_stream(StreamRef),
	logger:error("sent response ~p~nenc data ~p", [iolist_to_binary([<<1, DataLen>>, Data]), EncData]),
	State.

%% @todo In ignored_frame we must check for example that the frame
%%       we received wasn't the first frame in a control stream
%%       as that one must be SETTINGS.
ignored_frame(State, _) ->
	State.

stream_abort_receive(State, Stream=#stream{ref=StreamRef}, Reason) ->
	quicer:shutdown_stream(StreamRef, ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
		error_code(Reason), infinity),
	stream_update(State, Stream#stream{status=discard}).

%% @todo
terminate(_State, Error) ->
	exit({shutdown, Error}).

%% @todo qpack errors
error_code(h3_no_error) -> 16#0100;
error_code(h3_general_protocol_error) -> 16#0101;
error_code(h3_internal_error) -> 16#0102;
error_code(h3_stream_creation_error) -> 16#0103;
error_code(h3_closed_critical_stream) -> 16#0104;
error_code(h3_frame_unexpected) -> 16#0105;
error_code(h3_frame_error) -> 16#0106;
error_code(h3_excessive_load) -> 16#0107;
error_code(h3_id_error) -> 16#0108;
error_code(h3_settings_error) -> 16#0109;
error_code(h3_missing_settings) -> 16#010a;
error_code(h3_request_rejected) -> 16#010b;
error_code(h3_request_cancelled) -> 16#010c;
error_code(h3_request_incomplete) -> 16#010d;
error_code(h3_message_error) -> 16#010e;
error_code(h3_connect_error) -> 16#010f;
error_code(h3_version_fallback) -> 16#0110.

stream_new_remote(State=#state{http3_machine=HTTP3Machine0, streams=Streams}, StreamRef, Flags) ->
	{ok, StreamID} = quicer:get_stream_id(StreamRef),
	{StreamDir, StreamType, Status} = case quicer:is_unidirectional(Flags) of
		true -> {unidi_remote, undefined, header};
		false -> {bidi, req, normal}
	end,
	HTTP3Machine = cow_http3_machine:init_stream(StreamRef,
		StreamID, StreamDir, StreamType, HTTP3Machine0),
	Stream = #stream{ref=StreamRef, status=Status},
	logger:error("new stream ~p ~p", [Stream, HTTP3Machine]),
	State#state{http3_machine=HTTP3Machine, streams=Streams#{StreamRef => Stream}}.

stream_closed(State=#state{streams=Streams0}, StreamRef, _Flags) ->
	%% @todo Some streams may not be bidi or remote. Need to inform cow_http3_machine too.
	logger:error("stream_closed ~p", [StreamRef]),
	Streams = maps:remove(StreamRef, Streams0),
	%% @todo terminate stream
	State#state{streams=Streams}.

stream_update(State=#state{streams=Streams}, Stream=#stream{ref=StreamRef}) ->
	State#state{streams=Streams#{StreamRef => Stream}}.
