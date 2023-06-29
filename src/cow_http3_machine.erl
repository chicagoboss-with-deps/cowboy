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
-export([init_unidi_local_streams/7]).
-export([init_stream/5]).
-export([set_unidi_remote_stream_type/3]).
-export([frame/4]).
-export([prepare_headers/5]).

-record(stream, {
	ref :: any(), %% @todo specs
	id = undefined :: non_neg_integer(), %% @todo spec from quicer?
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

	%% Quick pointers for commonly used streams.
	local_encoder_ref :: any(), %% @todo specs
	local_decoder_ref :: any(), %% @todo specs

	%% Currently active HTTP/3 streams. Streams may be initiated either
	%% by the client or by the server through PUSH_PROMISE frames.
	streams = #{} :: #{reference() => stream()},

	%% QPACK decoding and encoding state.
	decode_state = cow_qpack:init() :: cow_qpack:state(),
	encode_state = cow_qpack:init() :: cow_qpack:state()
}).

-spec init(_, _) -> _. %% @todo

init(Mode, _Opts) ->
	{ok, <<>>, #http3_machine{mode=Mode}}.

-spec init_unidi_local_streams(_, _, _, _, _ ,_ ,_) -> _. %% @todo

init_unidi_local_streams(ControlRef, ControlID,
		EncoderRef, EncoderID, DecoderRef, DecoderID,
		State=#http3_machine{streams=Streams}) ->
	State#http3_machine{
		local_encoder_ref=EncoderRef,
		local_decoder_ref=DecoderRef,
		streams=Streams#{
			ControlRef => #stream{ref=ControlRef, id=ControlID, dir=unidi_local, type=control},
			EncoderRef => #stream{ref=EncoderRef, id=EncoderID, dir=unidi_local, type=encoder},
			DecoderRef => #stream{ref=DecoderRef, id=DecoderID, dir=unidi_local, type=decoder}
	}}.

-spec init_stream(_, _, _, _, _) -> _. %% @todo

init_stream(StreamRef, StreamID, StreamDir, StreamType,
		State=#http3_machine{streams=Streams}) ->
	State#http3_machine{streams=Streams#{StreamRef => #stream{
		ref=StreamRef, id=StreamID, dir=StreamDir, type=StreamType}}}.

-spec set_unidi_remote_stream_type(_, _, _) -> _. %% @todo

set_unidi_remote_stream_type(StreamRef, Type,
		State=#http3_machine{streams=Streams}) ->
	#{StreamRef := Stream} = Streams,
	State#http3_machine{streams=Streams#{StreamRef => Stream#stream{type=Type}}}.

-spec frame(_, _, _, _) -> _. %% @todo

frame(Frame, IsFin, StreamRef, State) ->
	case element(1, Frame) of
		headers -> headers_frame(Frame, IsFin, StreamRef, State);
		settings -> {ok, State} %% @todo
	end.

headers_frame(Frame, IsFin, StreamRef, State=#http3_machine{mode=Mode}) ->
	case Mode of
		server -> server_headers_frame(Frame, IsFin, StreamRef, State)
	end.

%% @todo We may receive HEADERS before or after DATA.
server_headers_frame(Frame, IsFin, StreamRef, State=#http3_machine{streams=Streams}) ->
	case Streams of
		%% Headers.
		#{StreamRef := Stream=#stream{remote=idle}} ->
			headers_decode(Frame, IsFin, Stream, State, request);
		%% Trailers.
		%% @todo Error out if we didn't get the full body.
		#{StreamRef := _Stream=#stream{remote=nofin}} ->
			todo_trailers; %% @todo
		%% Additional frame received after trailers.
		#{StreamRef := _Stream=#stream{remote=fin}} ->
			todo_error %% @todo
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

headers_pseudo_headers(Stream, State,%=#http3_machine{local_settings=LocalSettings},
		IsFin, Type, DecData, Headers0) when Type =:= request ->%; Type =:= push_promise ->
%	IsExtendedConnectEnabled = maps:get(enable_connect_protocol, LocalSettings, false),
	case request_pseudo_headers(Headers0, #{}) of
		%% Extended CONNECT method (RFC9220).
%		{ok, PseudoHeaders=#{method := <<"CONNECT">>, scheme := _,
%			authority := _, path := _, protocol := _}, Headers}
%			when IsExtendedConnectEnabled ->
%			headers_regular_headers(Frame, State, Type, Stream, PseudoHeaders, Headers);
%		{ok, #{method := <<"CONNECT">>, scheme := _,
%			authority := _, path := _}, _}
%			when IsExtendedConnectEnabled ->
%			headers_malformed(Stream, State,
%				'The :protocol pseudo-header MUST be sent with an extended CONNECT. (RFC8441 4)');
		{ok, #{protocol := _}, _} ->
			headers_malformed(Stream, State,
				'The :protocol pseudo-header is only defined for the extended CONNECT. (RFC8441 4)');
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

headers_malformed(#stream{id=StreamID}, State, HumanReadable) ->
	{error, {stream_error, StreamID, h3_message_error, HumanReadable}, State}.

%% Rejecting invalid regular headers might be a bit too strong for clients.
headers_regular_headers(Stream=#stream{id=_StreamID},
		State, IsFin, Type, DecData, PseudoHeaders, Headers) ->
	case regular_headers(Headers, Type) of
		ok when Type =:= request ->
			request_expected_size(Stream, State, IsFin, Type, DecData, PseudoHeaders, Headers);
%		ok when Type =:= push_promise ->
%			push_promise_frame(Frame, State, Stream, PseudoHeaders, Headers);
%		ok when Type =:= response ->
%			response_expected_size(Frame, State, Type, Stream, PseudoHeaders, Headers);
%		ok when Type =:= trailers ->
%			trailers_frame(Frame, State, Stream, Headers);
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
		[<<"0">>] when IsFin =:= fin ->
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

headers_parse_expected_size(Stream=#stream{id=_StreamID},
		State, IsFin, Type, DecData, PseudoHeaders, Headers, BinLen) ->
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

headers_frame(Stream0, State0=#http3_machine{local_decoder_ref=DecoderRef},
		IsFin, Type, DecData, PseudoHeaders, Headers, Len) ->
	Stream = case Type of
		request ->
			TE = case lists:keyfind(<<"te">>, 1, Headers) of
				{_, TE0} -> TE0;
				false -> undefined
			end,
			Stream0#stream{method=maps:get(method, PseudoHeaders),
				remote=IsFin, remote_expected_size=Len, te=TE}%;
%		response ->
%			Stream1 = case PseudoHeaders of
%				#{status := Status} when Status >= 100, Status =< 199 -> Stream0;
%				_ -> Stream0#stream{remote=IsFin, remote_expected_size=Len}
%			end,
%			{Stream1, State0}
	end,
	State = stream_store(Stream, State0),
	%% @todo Maybe don't return DecData if empty, but return the StreamRef with it if we must send.
	case DecData of
		<<>> ->
			{ok, {headers, IsFin, Headers, PseudoHeaders, Len}, State};
		_ ->
			{ok, {headers, IsFin, Headers, PseudoHeaders, Len}, {DecoderRef, DecData}, State}
	end.

%% Functions for sending a message header or body. Note that
%% this module does not send data directly, instead it returns
%% a value that can then be used to send the frames.

%-spec prepare_headers(cow_http2:streamid(), State, idle | cow_http2:fin(),
%	pseudo_headers(), cow_http:headers())
%	-> {ok, cow_http2:fin(), iodata(), State} when State::http2_machine().
-spec prepare_headers(_, _, _, _, _) -> todo.

prepare_headers(StreamRef, State=#http3_machine{encode_state=EncodeState0},
		IsFin0, PseudoHeaders, Headers0) ->
	Stream = #stream{id=StreamID, method=Method, local=idle} = stream_get(StreamRef, State),
	IsFin = case {IsFin0, Method} of
		{idle, _} -> nofin;
		{_, <<"HEAD">>} -> fin;
		_ -> IsFin0
	end,
	Headers = merge_pseudo_headers(PseudoHeaders, remove_http11_headers(Headers0)),
	{ok, HeaderBlock, EncData, EncodeState} = cow_qpack:encode_field_section(Headers, StreamID, EncodeState0),
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

%% Stream-related functions.

stream_get(StreamRef, #http3_machine{streams=Streams}) ->
	maps:get(StreamRef, Streams, undefined).

stream_store(#stream{ref=StreamRef, local=fin, remote=fin},
		State=#http3_machine{streams=Streams0}) ->
	Streams = maps:remove(StreamRef, Streams0),
	State#http3_machine{streams=Streams};
stream_store(Stream=#stream{ref=StreamRef},
		State=#http3_machine{streams=Streams}) ->
	State#http3_machine{streams=Streams#{StreamRef => Stream}}.
