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
	id :: non_neg_integer(), %% @todo specs
	dir :: unidi_local | unidi_remote | bidi,
	ref :: any(), %% @todo specs
	role :: undefined | req | control | push | encoder | decoder
}).

-record(state, {
	parent :: pid(),
	conn :: any(), %% @todo specs

	%% Quick pointers for commonly used streams.
	local_encoder_stream :: any(), %% @todo specs

	%% Bidirectional streams are used for requests and responses.
	streams = #{} :: map() %% @todo specs
}).

-spec init(_, _) -> no_return().
init(Parent, Conn) ->
	{ok, Conn} = quicer:async_accept_stream(Conn, []),
	%% Immediately open a control, encoder and decoder stream.
	{ok, ControlRef} = quicer:start_stream(Conn,
		#{open_flag => ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}),
	quicer:send(ControlRef, <<0>>), %% @todo Also send settings frame.
	{ok, ControlID} = quicer:get_stream_id(ControlRef),
	{ok, EncoderRef} = quicer:start_stream(Conn,
		#{open_flag => ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}),
	quicer:send(EncoderRef, <<2>>),
	{ok, EncoderID} = quicer:get_stream_id(EncoderRef),
	{ok, DecoderRef} = quicer:start_stream(Conn,
		#{open_flag => ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}),
	quicer:send(DecoderRef, <<3>>),
	{ok, DecoderID} = quicer:get_stream_id(DecoderRef),
	%% Quick! Let's go!
	loop(#state{parent=Parent, conn=Conn, local_encoder_stream=EncoderRef, streams=#{
		ControlRef => #stream{id=ControlID, dir=unidi_local, ref=ControlRef, role=control},
		EncoderRef => #stream{id=EncoderID, dir=unidi_local, ref=EncoderRef, role=encoder},
		DecoderRef => #stream{id=DecoderID, dir=unidi_local, ref=DecoderRef, role=decoder}
	}}).

loop(State0=#state{conn=Conn}) ->
	receive
		%% Stream data.
		{quic, Data, StreamRef, Props} when is_binary(Data) ->
			State = stream_data(Data, State0, StreamRef, Props),
			loop(State);
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

stream_new_remote(State=#state{streams=Streams}, StreamRef, Flags) ->
	{ok, StreamID} = quicer:get_stream_id(StreamRef),
	{StreamDir, Role} = case quicer:is_unidirectional(Flags) of
		true -> {unidi_remote, undefined};
		false -> {bidi, req}
	end,
	Stream = #stream{id=StreamID, dir=StreamDir, ref=StreamRef, role=Role},
	logger:debug("new stream ~p", [Stream]),
	State#state{streams=Streams#{StreamRef => Stream}}.

stream_data(Data, State=#state{streams=Streams}, StreamRef, _Props) ->
	#{StreamRef := Stream} = Streams,
	stream_data2(Data, State, Stream).

stream_data2(Data, State, Stream=#stream{role=req}) ->
	stream_data_req(State, Data, Stream);
stream_data2(_Data, State, _Stream=#stream{role=control}) ->
	State; %stream_data_control(...);
stream_data2(_Data, State, _Stream=#stream{role=encoder}) ->
	State; %stream_data_encoder(...);
stream_data2(_Data, State, _Stream=#stream{role=decoder}) ->
	State; %stream_data_decoder(...);
stream_data2(Data, State, Stream=#stream{role=undefined, dir=unidi_remote}) ->
	stream_data_undefined(State, Data, Stream).

%% @todo Frame type and length are using https://www.rfc-editor.org/rfc/rfc9000.html#name-variable-length-integer-enc
%% @todo Check stream state and update it afterwards.
stream_data_req(State=#state{local_encoder_stream=EncoderRef},
		Req = <<1, _Len, FieldsBin/binary>>, #stream{ref=StreamRef}) ->
	logger:debug("data ~p~nfields ~p", [Req, cow_qpack:decode_field_section(FieldsBin, 0, cow_qpack:init())]),
	StreamID = quicer:get_stream_id(StreamRef),
	{ok, Data, EncData, _} = cow_qpack:encode_field_section([
		{<<":status">>, <<"200">>},
		{<<"content-length">>, <<"12">>},
		{<<"content-type">>, <<"text/plain">>}
	], StreamID, cow_qpack:init()),
	%% Send the encoder data.
	quicer:send(EncoderRef, EncData),
	%% Then the response data.
	DataLen = iolist_size(Data),
	quicer:send(StreamRef, [<<1, DataLen>>, Data]),
	quicer:send(StreamRef, <<0,12,"Hello world!">>, ?QUIC_SEND_FLAG_FIN),
%	quicer:shutdown_stream(StreamRef),
	logger:debug("sent response ~p~nenc data ~p", [iolist_to_binary([<<1, DataLen>>, Data]), EncData]),
	State.

%% @todo stream_control
%% @todo stream_encoder
%% @todo stream_decoder

%% @todo We should probably reject, not crash, unknown/bad types.
stream_data_undefined(State, <<TypeBin, Rest/bits>>, Stream0) ->
	Role = case TypeBin of
		0 -> control;
		2 -> encoder;
		3 -> decoder
	end,
	Stream = Stream0#stream{role=Role},
	stream_data2(Rest, stream_update(State, Stream), Stream).

stream_closed(State=#state{streams=Streams0}, StreamRef, _Flags) ->
	{_Stream, Streams} = maps:take(StreamRef, Streams0),
	%% @todo terminate stream
	State#state{streams=Streams}.

stream_update(State=#state{streams=Streams}, Stream=#stream{ref=StreamRef}) ->
	State#state{streams=Streams#{StreamRef => Stream}}.
