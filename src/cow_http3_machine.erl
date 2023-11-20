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

-module(cow_http3_machine).

-export([init/2]).
-export([init_unidi_local_streams/4]).
-export([init_unidi_stream/3]).
-export([set_unidi_remote_stream_type/3]).
-export([init_bidi_stream/2]).
-export([init_bidi_stream/3]).
-export([close_bidi_stream_for_sending/2]).
-export([close_stream/2]).
-export([frame/4]).
-export([ignored_frame/2]).
-export([prepare_headers/5]).
-export([prepare_trailers/3]).
-export([reset_stream/2]).
-export([get_stream_local_state/2]).
-export([get_stream_remote_state/2]).

-record(stream, {
	id :: non_neg_integer(),
	dir :: unidi_local | unidi_remote | bidi,
	type :: undefined | req | control | push | encoder | decoder,

	%% Further fields are only used by bidi streams.
	%% @todo Perhaps have two different records?

	%% Request method.
	method = undefined :: binary(),

	%% Whether we finished sending data.
	local = idle :: idle | cow_http2:fin(),

	%% Whether we finished receiving data.
	remote = idle :: idle | cow_http2:fin(),

	%% Size expected and read from the request body.
	remote_expected_size = undefined :: undefined | non_neg_integer(),
	remote_read_size = 0 :: non_neg_integer(),

	%% Unparsed te header. Used to know if we can send trailers.
	%% Note that we can always send trailers to the server.
	te :: undefined | binary()
}).

-type stream() :: #stream{}.

-record(http3_machine, {
	%% Whether the HTTP/3 endpoint is a client or a server.
	mode :: client | server,

	%% Maximum Push ID.
	max_push_id = -1 :: -1 | non_neg_integer(),

	%% Settings are separate for each endpoint. They are sent once
	%% at the beginning of the control stream.
	local_settings = #{
%		max_field_section_size => infinity
%		enable_connect_protocol => false
	} :: map(),

	%% Currently active HTTP/3 streams. Streams may be initiated either
	%% by the client or by the server through PUSH_PROMISE frames.
	streams = #{} :: #{non_neg_integer() => stream()},
	%% @todo Maybe merge these two in some kind of control stream state.
	has_peer_control_stream = false :: boolean(),
	has_received_peer_settings = false :: boolean(),

	%% QPACK decoding and encoding state.
	decode_state = cow_qpack:init() :: cow_qpack:state(),
	encode_state = cow_qpack:init() :: cow_qpack:state()
}).

-spec init(_, _) -> _. %% @todo

init(Mode, Opts) ->
	Settings = settings_init(Opts),
	{ok, cow_http3:settings(Settings),
		#http3_machine{mode=Mode, local_settings=Settings}}.

settings_init(Opts) ->
	S0 = setting_from_opt(#{}, Opts, max_field_section_size, infinity),
	setting_from_opt(S0, Opts, enable_connect_protocol, false).

setting_from_opt(Settings, Opts, Name, Default) ->
	case maps:get(Name, Opts, Default) of
		Default -> Settings;
		Value -> Settings#{Name => Value}
	end.

-spec init_unidi_local_streams(_, _ ,_ ,_) -> _. %% @todo

init_unidi_local_streams(ControlID, EncoderID, DecoderID,
		State=#http3_machine{streams=Streams}) ->
	State#http3_machine{
		streams=Streams#{
			ControlID => #stream{id=ControlID, dir=unidi_local, type=control},
			EncoderID => #stream{id=EncoderID, dir=unidi_local, type=encoder},
			DecoderID => #stream{id=DecoderID, dir=unidi_local, type=decoder}
	}}.

-spec init_unidi_stream(_, _, _) -> _. %% @todo

init_unidi_stream(StreamID, StreamDir, State=#http3_machine{streams=Streams}) ->
	State#http3_machine{streams=Streams#{StreamID => #stream{
		id=StreamID, dir=StreamDir, type=undefined}}}.

-spec set_unidi_remote_stream_type(_, _, _) -> _. %% @todo

set_unidi_remote_stream_type(_, control, State=#http3_machine{has_peer_control_stream=true}) ->
	{error, {connection_error, h3_stream_creation_error,
		'There can be only one control stream; yet a second one was opened. (RFC9114 6.2.1)'},
		State};
set_unidi_remote_stream_type(StreamID, Type,
		State=#http3_machine{streams=Streams, has_peer_control_stream=HasControl}) ->
	#{StreamID := Stream} = Streams,
	{ok, State#http3_machine{
		streams=Streams#{StreamID => Stream#stream{type=Type}},
		has_peer_control_stream=HasControl orelse (Type =:= control)
	}}.

-spec init_bidi_stream(_, _) -> _. %% @todo

%% All bidi streams are request/response.
init_bidi_stream(StreamID, State=#http3_machine{streams=Streams}) ->
	State#http3_machine{streams=Streams#{StreamID => #stream{
		id=StreamID, dir=bidi, type=req}}}.

-spec init_bidi_stream(_, _, _) -> _. %% @todo

%% All bidi streams are request/response.
init_bidi_stream(StreamID, Method, State=#http3_machine{streams=Streams}) ->
	State#http3_machine{streams=Streams#{StreamID => #stream{
		id=StreamID, dir=bidi, type=req, method=Method}}}.

%% @todo set_bidi_method?

-spec close_bidi_stream_for_sending(_, _) -> _. %% @todo

close_bidi_stream_for_sending(StreamID, State=#http3_machine{streams=Streams}) ->
	#{StreamID := Stream} = Streams,
	stream_store(Stream#stream{local=fin}, State).

-spec close_stream(_, _) -> _. %% @todo

close_stream(StreamID, State=#http3_machine{streams=Streams0}) ->
%	ct:pal("~p close_stream ~p ~p", [self(), StreamID, Streams0]),
	case maps:take(StreamID, Streams0) of
		{#stream{type=control}, Streams} ->
			{error, {connection_error, h3_closed_critical_stream,
				'The control stream was closed. (RFC9114 6.2.1)'},
				State#http3_machine{streams=Streams}};
		%% @todo We should also error out when the QPACK streams get closed.
		{_, Streams} ->
			{ok, State#http3_machine{streams=Streams}}
	end.

-spec frame(_, _, _, _) -> _. %% @todo

frame(Frame, IsFin, StreamID, State) ->
	case element(1, Frame) of
		data -> data_frame(Frame, IsFin, StreamID, State);
		headers -> headers_frame(Frame, IsFin, StreamID, State);
		cancel_push -> cancel_push_frame(Frame, IsFin, StreamID, State);
		settings -> settings_frame(Frame, IsFin, StreamID, State);
		push_promise -> push_promise_frame(Frame, IsFin, StreamID, State);
		goaway -> goaway_frame(Frame, IsFin, StreamID, State);
		max_push_id -> max_push_id_frame(Frame, IsFin, StreamID, State)
	end.

%% DATA frame.

data_frame(Frame={data, Data}, IsFin, StreamID, State) ->
	DataLen = byte_size(Data),
	case stream_get(StreamID, State) of
		Stream = #stream{type=req, remote=nofin} ->
			data_frame(Frame, IsFin, Stream, State, DataLen);
		#stream{type=req, remote=idle} ->
			{error, {connection_error, h3_frame_unexpected,
				'DATA frame received before a HEADERS frame. (RFC9114 4.1)'},
				State};
		#stream{type=req, remote=fin} ->
			{error, {connection_error, h3_frame_unexpected,
				'DATA frame received after trailer HEADERS frame. (RFC9114 4.1)'},
				State};
		#stream{type=control} ->
			control_frame(Frame, State)
	end.

data_frame(Frame, IsFin, Stream0=#stream{remote_read_size=StreamRead}, State0, DataLen) ->
	Stream = Stream0#stream{remote=IsFin,
		remote_read_size=StreamRead + DataLen},
	State = stream_store(Stream, State0),
	case is_body_size_valid(Stream) of
		true ->
			{ok, Frame, State}%;
%		false ->
%			stream_reset(StreamID, State, protocol_error,
%				'The total size of DATA frames is different than the content-length. (RFC7540 8.1.2.6)')
	end.

%% It's always valid when no content-length header was specified.
is_body_size_valid(#stream{remote_expected_size=undefined}) ->
	true;
%% We didn't finish reading the body but the size is already larger than expected.
is_body_size_valid(#stream{remote=nofin, remote_expected_size=Expected,
		remote_read_size=Read}) when Read > Expected ->
	false;
is_body_size_valid(#stream{remote=nofin}) ->
	true;
is_body_size_valid(#stream{remote=fin, remote_expected_size=Expected,
		remote_read_size=Expected}) ->
	true;
%% We finished reading the body and the size read is not the one expected.
is_body_size_valid(_) ->
	false.

%% HEADERS frame.

headers_frame(Frame, IsFin, StreamID, State=#http3_machine{mode=Mode}) ->
	case stream_get(StreamID, State) of
		%% Headers.
		Stream=#stream{type=req, remote=idle} ->
			headers_decode(Frame, IsFin, Stream, State, case Mode of
				server -> request;
				client -> response
			end);
		%% Trailers.
		Stream=#stream{type=req, remote=nofin} ->
			headers_decode(Frame, IsFin, Stream, State, trailers);
		%% Additional frame received after trailers.
		#stream{type=req, remote=fin} ->
			{error, {connection_error, h3_frame_unexpected,
				'HEADERS frame received after trailer HEADERS frame. (RFC9114 4.1)'},
				State};
		#stream{type=control} ->
			control_frame(Frame, State)
	end.

%% @todo Check whether connection_error or stream_error fits better.
headers_decode({headers, EncodedFieldSection}, IsFin, Stream=#stream{id=StreamID},
		State=#http3_machine{decode_state=DecodeState0}, Type) ->
	try cow_qpack:decode_field_section(EncodedFieldSection, StreamID, DecodeState0) of
		{ok, Headers, DecData, DecodeState} ->
			headers_pseudo_headers(Stream,
				State#http3_machine{decode_state=DecodeState}, IsFin, Type, DecData, Headers);
		{error, Reason, Human} ->
			{error, {connection_error, Reason, Human}, State}
	catch _:_ ->
		{error, {connection_error, qpack_decompression_failed,
			'Error while trying to decode QPACK-encoded header block. (RFC9204 6)'},
			State}
	end.

%% @todo Much of the headers handling past this point is common between h2 and h3.

headers_pseudo_headers(Stream, State=#http3_machine{local_settings=LocalSettings},
		IsFin, Type, DecData, Headers0) when Type =:= request ->%; Type =:= push_promise ->
	IsExtendedConnectEnabled = maps:get(enable_connect_protocol, LocalSettings, false),
	case request_pseudo_headers(Headers0, #{}) of
		%% Extended CONNECT method (RFC9220).
		{ok, PseudoHeaders=#{method := <<"CONNECT">>, scheme := _,
			authority := _, path := _, protocol := _}, Headers}
			when IsExtendedConnectEnabled ->
			headers_regular_headers(Stream, State, IsFin, Type, DecData, PseudoHeaders, Headers);
		{ok, #{method := <<"CONNECT">>, scheme := _,
			authority := _, path := _}, _}
			when IsExtendedConnectEnabled ->
			headers_malformed(Stream, State,
				'The :protocol pseudo-header MUST be sent with an extended CONNECT. (RFC9220, RFC8441 4)');
		{ok, #{protocol := _}, _} ->
			headers_malformed(Stream, State,
				'The :protocol pseudo-header is only defined for the extended CONNECT. (RFC9220, RFC8441 4)');
		%% Normal CONNECT (no scheme/path).
		{ok, PseudoHeaders=#{method := <<"CONNECT">>, authority := _}, Headers}
				when map_size(PseudoHeaders) =:= 2 ->
			headers_regular_headers(Stream, State, IsFin, Type, DecData, PseudoHeaders, Headers);
		{ok, #{method := <<"CONNECT">>}, _} ->
			headers_malformed(Stream, State,
				'CONNECT requests only use the :method and :authority pseudo-headers. (RFC7540 8.3)');
		%% Other requests.
		{ok, PseudoHeaders=#{method := _, scheme := _, path := _}, Headers} ->
			headers_regular_headers(Stream, State, IsFin, Type, DecData, PseudoHeaders, Headers);
		{ok, _, _} ->
			headers_malformed(Stream, State,
				'A required pseudo-header was not found. (RFC7540 8.1.2.3)');
		{error, HumanReadable} ->
			headers_malformed(Stream, State, HumanReadable)
	end;
headers_pseudo_headers(Stream, State, IsFin, Type=response, DecData, Headers0) ->
	case response_pseudo_headers(Headers0, #{}) of
		{ok, PseudoHeaders=#{status := _}, Headers} ->
			headers_regular_headers(Stream, State, IsFin, Type, DecData, PseudoHeaders, Headers);
		{ok, _, _} ->
			{error, {stream_error, protocol_error,
				'A required pseudo-header was not found. (RFC7540 8.1.2.4)'},
				State};
		{error, HumanReadable} ->
			{error, {stream_error, protocol_error, HumanReadable}, State}
	end;
headers_pseudo_headers(Stream, State, IsFin, Type=trailers, DecData, Headers) ->
	case trailers_contain_pseudo_headers(Headers) of
		false ->
			headers_regular_headers(Stream, State, IsFin, Type, DecData, #{}, Headers);
		true ->
			{error, {stream_error, h3_message_error,
				'Trailer header blocks must not contain pseudo-headers. (RFC9114 4.3)'},
				State}
	end.

%% @todo This function was copy pasted from cow_http2_machine. Export instead.
request_pseudo_headers([{<<":method">>, _}|_], #{method := _}) ->
	{error, 'Multiple :method pseudo-headers were found. (RFC7540 8.1.2.3)'};
request_pseudo_headers([{<<":method">>, Method}|Tail], PseudoHeaders) ->
	request_pseudo_headers(Tail, PseudoHeaders#{method => Method});
request_pseudo_headers([{<<":scheme">>, _}|_], #{scheme := _}) ->
	{error, 'Multiple :scheme pseudo-headers were found. (RFC7540 8.1.2.3)'};
request_pseudo_headers([{<<":scheme">>, Scheme}|Tail], PseudoHeaders) ->
	request_pseudo_headers(Tail, PseudoHeaders#{scheme => Scheme});
request_pseudo_headers([{<<":authority">>, _}|_], #{authority := _}) ->
	{error, 'Multiple :authority pseudo-headers were found. (RFC7540 8.1.2.3)'};
request_pseudo_headers([{<<":authority">>, Authority}|Tail], PseudoHeaders) ->
	request_pseudo_headers(Tail, PseudoHeaders#{authority => Authority});
request_pseudo_headers([{<<":path">>, _}|_], #{path := _}) ->
	{error, 'Multiple :path pseudo-headers were found. (RFC7540 8.1.2.3)'};
request_pseudo_headers([{<<":path">>, Path}|Tail], PseudoHeaders) ->
	request_pseudo_headers(Tail, PseudoHeaders#{path => Path});
request_pseudo_headers([{<<":protocol">>, _}|_], #{protocol := _}) ->
	{error, 'Multiple :protocol pseudo-headers were found. (RFC7540 8.1.2.3)'};
request_pseudo_headers([{<<":protocol">>, Protocol}|Tail], PseudoHeaders) ->
	request_pseudo_headers(Tail, PseudoHeaders#{protocol => Protocol});
request_pseudo_headers([{<<":", _/bits>>, _}|_], _) ->
	{error, 'An unknown or invalid pseudo-header was found. (RFC7540 8.1.2.1)'};
request_pseudo_headers(Headers, PseudoHeaders) ->
	{ok, PseudoHeaders, Headers}.

response_pseudo_headers([{<<":status">>, _}|_], #{status := _}) ->
	{error, 'Multiple :status pseudo-headers were found. (RFC7540 8.1.2.3)'};
response_pseudo_headers([{<<":status">>, Status}|Tail], PseudoHeaders) ->
	try cow_http:status_to_integer(Status) of
		IntStatus ->
			response_pseudo_headers(Tail, PseudoHeaders#{status => IntStatus})
	catch _:_ ->
		{error, 'The :status pseudo-header value is invalid. (RFC7540 8.1.2.4)'}
	end;
response_pseudo_headers([{<<":", _/bits>>, _}|_], _) ->
	{error, 'An unknown or invalid pseudo-header was found. (RFC7540 8.1.2.1)'};
response_pseudo_headers(Headers, PseudoHeaders) ->
	{ok, PseudoHeaders, Headers}.

trailers_contain_pseudo_headers([]) ->
	false;
trailers_contain_pseudo_headers([{<<":", _/bits>>, _}|_]) ->
	true;
trailers_contain_pseudo_headers([_|Tail]) ->
	trailers_contain_pseudo_headers(Tail).

headers_malformed(#stream{}, State, HumanReadable) ->
	%% @todo StreamID?
	{error, {stream_error, h3_message_error, HumanReadable}, State}.

%% Rejecting invalid regular headers might be a bit too strong for clients.
headers_regular_headers(Stream=#stream{},
		State, IsFin, Type, DecData, PseudoHeaders, Headers) ->
	case regular_headers(Headers, Type) of
		ok when Type =:= request ->
			request_expected_size(Stream, State, IsFin, Type, DecData, PseudoHeaders, Headers);
%		ok when Type =:= push_promise ->
%			push_promise_frame(Frame, State, Stream, PseudoHeaders, Headers);
		ok when Type =:= response ->
			response_expected_size(Stream, State, IsFin, Type, DecData, PseudoHeaders, Headers);
		ok when Type =:= trailers ->
			trailers_frame(Stream, State, DecData, Headers);
		{error, HumanReadable} when Type =:= request ->
			headers_malformed(Stream, State, HumanReadable)%;
%		{error, HumanReadable} ->
%			stream_reset(StreamID, State, protocol_error, HumanReadable)
	end.

%% @todo This function was copy pasted from cow_http2_machine. Export instead.
%% @todo The error reasons refer to the h2 RFC but then again h3 doesn't cover it in as much details.
regular_headers([{<<>>, _}|_], _) ->
	{error, 'Empty header names are not valid regular headers. (CVE-2019-9516)'};
regular_headers([{<<":", _/bits>>, _}|_], _) ->
	{error, 'Pseudo-headers were found after regular headers. (RFC7540 8.1.2.1)'};
regular_headers([{<<"connection">>, _}|_], _) ->
	{error, 'The connection header is not allowed. (RFC7540 8.1.2.2)'};
regular_headers([{<<"keep-alive">>, _}|_], _) ->
	{error, 'The keep-alive header is not allowed. (RFC7540 8.1.2.2)'};
regular_headers([{<<"proxy-authenticate">>, _}|_], _) ->
	{error, 'The proxy-authenticate header is not allowed. (RFC7540 8.1.2.2)'};
regular_headers([{<<"proxy-authorization">>, _}|_], _) ->
	{error, 'The proxy-authorization header is not allowed. (RFC7540 8.1.2.2)'};
regular_headers([{<<"transfer-encoding">>, _}|_], _) ->
	{error, 'The transfer-encoding header is not allowed. (RFC7540 8.1.2.2)'};
regular_headers([{<<"upgrade">>, _}|_], _) ->
	{error, 'The upgrade header is not allowed. (RFC7540 8.1.2.2)'};
regular_headers([{<<"te">>, Value}|_], request) when Value =/= <<"trailers">> ->
	{error, 'The te header with a value other than "trailers" is not allowed. (RFC7540 8.1.2.2)'};
regular_headers([{<<"te">>, _}|_], Type) when Type =/= request ->
	{error, 'The te header is only allowed in request headers. (RFC7540 8.1.2.2)'};
regular_headers([{Name, _}|Tail], Type) ->
	Pattern = [
		<<$A>>, <<$B>>, <<$C>>, <<$D>>, <<$E>>, <<$F>>, <<$G>>, <<$H>>, <<$I>>,
		<<$J>>, <<$K>>, <<$L>>, <<$M>>, <<$N>>, <<$O>>, <<$P>>, <<$Q>>, <<$R>>,
		<<$S>>, <<$T>>, <<$U>>, <<$V>>, <<$W>>, <<$X>>, <<$Y>>, <<$Z>>
	],
	case binary:match(Name, Pattern) of
		nomatch -> regular_headers(Tail, Type);
		_ -> {error, 'Header names must be lowercase. (RFC7540 8.1.2)'}
	end;
regular_headers([], _) ->
	ok.

%% @todo Much of the logic can probably be put in its own function shared between h2 and h3.
request_expected_size(Stream, State, IsFin, Type, DecData, PseudoHeaders, Headers) ->
	case [CL || {<<"content-length">>, CL} <- Headers] of
		[] when IsFin =:= fin ->
			headers_frame(Stream, State, IsFin, Type, DecData, PseudoHeaders, Headers, 0);
		[] ->
			headers_frame(Stream, State, IsFin, Type, DecData, PseudoHeaders, Headers, undefined);
		[<<"0">>] ->
			headers_frame(Stream, State, IsFin, Type, DecData, PseudoHeaders, Headers, 0);
		[_] when IsFin =:= fin ->
			headers_malformed(Stream, State,
				'HEADERS frame with the END_STREAM flag contains a non-zero content-length. (RFC7540 8.1.2.6)');
		[BinLen] ->
			headers_parse_expected_size(Stream, State, IsFin, Type, DecData,
				PseudoHeaders, Headers, BinLen);
		_ ->
			headers_malformed(Stream, State,
				'Multiple content-length headers were received. (RFC7230 3.3.2)')
	end.

response_expected_size(Stream=#stream{method=Method}, State, IsFin, Type, DecData,
		PseudoHeaders=#{status := Status}, Headers) ->
	case [CL || {<<"content-length">>, CL} <- Headers] of
		[] when IsFin =:= fin ->
			headers_frame(Stream, State, IsFin, Type, DecData, PseudoHeaders, Headers, 0);
		[] ->
			headers_frame(Stream, State, IsFin, Type, DecData, PseudoHeaders, Headers, undefined);
		[_] when Status >= 100, Status =< 199 ->
			{error, {stream_error, protocol_error,
				'Content-length header received in a 1xx response. (RFC7230 3.3.2)'},
				State};
		[_] when Status =:= 204 ->
			{error, {stream_error, protocol_error,
				'Content-length header received in a 204 response. (RFC7230 3.3.2)'},
				State};
		[_] when Status >= 200, Status =< 299, Method =:= <<"CONNECT">> ->
			{error, {stream_error, protocol_error,
				'Content-length header received in a 2xx response to a CONNECT request. (RFC7230 3.3.2).'},
				State};
		%% Responses to HEAD requests, and 304 responses may contain
		%% a content-length header that must be ignored. (RFC7230 3.3.2)
		[_] when Method =:= <<"HEAD">> ->
			headers_frame(Stream, State, IsFin, Type, DecData, PseudoHeaders, Headers, 0);
		[_] when Status =:= 304 ->
			headers_frame(Stream, State, IsFin, Type, DecData, PseudoHeaders, Headers, 0);
		[<<"0">>] when IsFin =:= fin ->
			headers_frame(Stream, State, IsFin, Type, DecData, PseudoHeaders, Headers, 0);
		[_] when IsFin =:= fin ->
			{error, {stream_error, protocol_error,
				'HEADERS frame with the END_STREAM flag contains a non-zero content-length. (RFC7540 8.1.2.6)'},
				State};
		[BinLen] ->
			headers_parse_expected_size(Stream, State, IsFin, Type, DecData,
				PseudoHeaders, Headers, BinLen);
		_ ->
			{error, {stream_error, protocol_error,
				'Multiple content-length headers were received. (RFC7230 3.3.2)'},
				State}
	end.

headers_parse_expected_size(Stream, State, IsFin, Type, DecData,
		PseudoHeaders, Headers, BinLen) ->
	try cow_http_hd:parse_content_length(BinLen) of
		Len ->
			headers_frame(Stream, State, IsFin, Type, DecData, PseudoHeaders, Headers, Len)
	catch
		_:_ ->
			HumanReadable = 'The content-length header is invalid. (RFC7230 3.3.2)',
			case Type of
				request -> headers_malformed(Stream, State, HumanReadable)%;
%				response -> stream_reset(StreamID, State, protocol_error, HumanReadable)
			end
	end.

headers_frame(Stream0, State0, IsFin, Type, DecData, PseudoHeaders, Headers, Len) ->
	Stream = case Type of
		request ->
			TE = case lists:keyfind(<<"te">>, 1, Headers) of
				{_, TE0} -> TE0;
				false -> undefined
			end,
			Stream0#stream{method=maps:get(method, PseudoHeaders),
				remote=IsFin, remote_expected_size=Len, te=TE};
		response ->
			case PseudoHeaders of
				#{status := Status} when Status >= 100, Status =< 199 -> Stream0;
				_ -> Stream0#stream{remote=IsFin, remote_expected_size=Len}
			end
	end,
	State = stream_store(Stream, State0),
	case DecData of
		<<>> ->
			{ok, {headers, IsFin, Headers, PseudoHeaders, Len}, State};
		_ ->
			{ok, {headers, IsFin, Headers, PseudoHeaders, Len}, DecData, State}
	end.

trailers_frame(Stream0, State0, DecData, Headers) ->
	Stream = Stream0#stream{remote=fin},
	State = stream_store(Stream, State0),
	%% @todo Error out if we didn't get the full body.
%	case is_body_size_valid(Stream) of
%		true ->
			case DecData of
				<<>> ->
					{ok, {trailers, Headers}, State};
				_ ->
					{ok, {trailers, Headers}, DecData, State}
			end.%;
%		false ->
%			stream_reset(StreamID, State, protocol_error,
%				'The total size of DATA frames is different than the content-length. (RFC7540 8.1.2.6)')
%	end.

cancel_push_frame(Frame, _IsFin, StreamID, State) ->
	case stream_get(StreamID, State) of
		#stream{type=control} ->
			control_frame(Frame, State)
	end.

settings_frame(Frame, _IsFin, StreamID, State) ->
	case stream_get(StreamID, State) of
		#stream{type=control} ->
			control_frame(Frame, State);
		#stream{type=req} ->
			{error, {connection_error, h3_frame_unexpected,
				'The SETTINGS frame is not allowed on a bidi stream. (RFC9114 7.2.4)'},
				State}
	end.

push_promise_frame(Frame, _IsFin, StreamID, State) ->
	case stream_get(StreamID, State) of
		#stream{type=control} ->
			control_frame(Frame, State)
	end.

goaway_frame(Frame, _IsFin, StreamID, State) ->
	case stream_get(StreamID, State) of
		#stream{type=control} ->
			control_frame(Frame, State);
		#stream{type=req} ->
			{error, {connection_error, h3_frame_unexpected,
				'The GOAWAY frame is not allowed on a bidi stream. (RFC9114 7.2.6)'},
				State}
	end.

max_push_id_frame(Frame, _IsFin, StreamID, State) ->
	case stream_get(StreamID, State) of
		#stream{type=control} ->
			control_frame(Frame, State);
		#stream{type=req} ->
			{error, {connection_error, h3_frame_unexpected,
				'The MAX_PUSH_ID frame is not allowed on a bidi stream. (RFC9114 7.2.7)'},
				State}
	end.

control_frame({settings, _Settings}, State=#http3_machine{has_received_peer_settings=false}) ->
	{ok, State#http3_machine{has_received_peer_settings=true}};
control_frame({settings, _}, State) ->
	{error, {connection_error, h3_frame_unexpected,
		'The SETTINGS frame cannot be sent more than once. (RFC9114 7.2.4)'},
		State};
control_frame(_Frame, State=#http3_machine{has_received_peer_settings=false}) ->
	{error, {connection_error, h3_missing_settings,
		'The first frame on the control stream must be a SETTINGS frame. (RFC9114 6.2.1)'},
		State};
control_frame(Frame = {goaway, _}, State) ->
	{ok, Frame, State};
%% @todo Implement server push.
control_frame({max_push_id, PushID}, State=#http3_machine{max_push_id=MaxPushID}) ->
	if
		PushID >= MaxPushID ->
			{ok, State#http3_machine{max_push_id=PushID}};
		true ->
			{error, {connection_error, h3_id_error,
				'MAX_PUSH_ID must not be lower than previously received. (RFC9114 7.2.7)'},
				State}
	end;
control_frame(ignored_frame, State) ->
	{ok, State};
control_frame(_Frame, State) ->
	{error, {connection_error, h3_frame_unexpected,
		'DATA and HEADERS frames are not allowed on the control stream. (RFC9114 7.2.1, RFC9114 7.2.2)'},
		State}.

%% Ignored frames.

-spec ignored_frame(_, _) -> _. %% @todo

ignored_frame(StreamID, State) ->
	case stream_get(StreamID, State) of
		#stream{type=control} ->
			control_frame(ignored_frame, State);
		_ ->
			{ok, State}
	end.

%% Functions for sending a message header or body. Note that
%% this module does not send data directly, instead it returns
%% a value that can then be used to send the frames.

%-spec prepare_headers(cow_http2:streamid(), State, idle | cow_http2:fin(),
%	pseudo_headers(), cow_http:headers())
%	-> {ok, cow_http2:fin(), iodata(), State} when State::http2_machine().
-spec prepare_headers(_, _, _, _, _) -> todo.

prepare_headers(StreamID, State=#http3_machine{encode_state=EncodeState0},
		IsFin0, PseudoHeaders, Headers0) ->
	Stream = #stream{method=Method, local=idle} = stream_get(StreamID, State),
	IsFin = case {IsFin0, Method} of
		{idle, _} -> nofin;
		{_, <<"HEAD">>} -> fin;
		_ -> IsFin0
	end,
	Headers = merge_pseudo_headers(PseudoHeaders, remove_http11_headers(Headers0)),
	{ok, HeaderBlock, EncData, EncodeState} = cow_qpack:encode_field_section(Headers, StreamID, EncodeState0),
	%% @todo Return the EncoderRef with the EncData.
	{ok, IsFin, HeaderBlock, EncData, stream_store(Stream#stream{local=IsFin0},
		State#http3_machine{encode_state=EncodeState})}.

%% @todo Function copied from cow_http2_machine.
remove_http11_headers(Headers) ->
	RemoveHeaders0 = [
		<<"keep-alive">>,
		<<"proxy-connection">>,
		<<"transfer-encoding">>,
		<<"upgrade">>
	],
	RemoveHeaders = case lists:keyfind(<<"connection">>, 1, Headers) of
		false ->
			RemoveHeaders0;
		{_, ConnHd} ->
			%% We do not need to worry about any "close" header because
			%% that header name is reserved.
			Connection = cow_http_hd:parse_connection(ConnHd),
			Connection ++ [<<"connection">>|RemoveHeaders0]
	end,
	lists:filter(fun({Name, _}) ->
		not lists:member(Name, RemoveHeaders)
	end, Headers).

%% @todo Function copied from cow_http2_machine.
merge_pseudo_headers(PseudoHeaders, Headers0) ->
	lists:foldl(fun
		({status, Status}, Acc) when is_integer(Status) ->
			[{<<":status">>, integer_to_binary(Status)}|Acc];
		({Name, Value}, Acc) ->
			[{iolist_to_binary([$:, atom_to_binary(Name, latin1)]), Value}|Acc]
		end, Headers0, maps:to_list(PseudoHeaders)).

-spec prepare_trailers(_, _, _) -> todo.

prepare_trailers(StreamID, State=#http3_machine{encode_state=EncodeState0}, Trailers) ->
	Stream = #stream{local=nofin, te=TE0} = stream_get(StreamID, State),
	TE = try cow_http_hd:parse_te(TE0) of
		{trailers, []} -> trailers;
		_ -> no_trailers
	catch _:_ ->
		%% If we can't parse the TE header, assume we can't send trailers.
		no_trailers
	end,
	case TE of
		trailers ->
			{ok, HeaderBlock, EncData, EncodeState} = cow_qpack:encode_field_section(Trailers, StreamID, EncodeState0),
			{trailers, HeaderBlock, EncData, stream_store(Stream#stream{local=fin},
				State#http3_machine{encode_state=EncodeState})};
		no_trailers ->
			{no_trailers, stream_store(Stream#stream{local=fin}, State)}
	end.

%% Public interface to reset streams.

-spec reset_stream(_, _) -> todo.

reset_stream(StreamID, State=#http3_machine{streams=Streams0}) ->
	case maps:take(StreamID, Streams0) of
		{_, Streams} ->
			{ok, State#http3_machine{streams=Streams}};
		error ->
			{error, not_found}
	end.

%% Retrieve the local state for a stream.

-spec get_stream_local_state(_, _) -> todo.

get_stream_local_state(StreamID, State) ->
	case stream_get(StreamID, State) of
		#stream{local=IsFin} ->
			{ok, IsFin};
		%% Stream may never have been opened, or could have
		%% already been closed.
		undefined ->
			{error, not_found}
	end.

%% Retrieve the remote state for a stream.

-spec get_stream_remote_state(_, _) -> todo.

get_stream_remote_state(StreamID, State) ->
	case stream_get(StreamID, State) of
		#stream{remote=IsFin} ->
			{ok, IsFin};
		%% Stream may never have been opened, or could have
		%% already been closed.
		undefined ->
			{error, not_found}
	end.

%% Stream-related functions.

stream_get(StreamID, #http3_machine{streams=Streams}) ->
	maps:get(StreamID, Streams, undefined).

%stream_store(#stream{id=StreamID, local=fin, remote=fin},
%		State=#http3_machine{streams=Streams0}) ->
%	%% @todo We may want to wait for the QUIC message about stream closure.
%	Streams = maps:remove(StreamID, Streams0),
%	State#http3_machine{streams=Streams};
stream_store(Stream=#stream{id=StreamID},
		State=#http3_machine{streams=Streams}) ->
	State#http3_machine{streams=Streams#{StreamID => Stream}}.
