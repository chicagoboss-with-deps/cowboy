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

-module(rfc9114_SUITE).
-compile(export_all).
-compile(nowarn_export_all).

-import(ct_helper, [config/2]).
-import(ct_helper, [doc/1]).

-include_lib("quicer/include/quicer.hrl").

all() -> [{group, quic}].

groups() ->
	%% @todo Enable parallel tests but for this issues in the
	%% QUIC accept loop need to be figured out (can't connect
	%% concurrently somehow, no backlog?).
	[{quic, [], ct_helper:all(?MODULE)}].

init_per_group(Name = quic, Config) ->
	cowboy_test:init_http3(Name, #{
		env => #{dispatch => cowboy_router:compile(init_routes(Config))}
	}, Config).

end_per_group(_Name, _) ->
	ok. %% @todo = cowboy:stop_listener(Name).

init_routes(_) -> [
	{"localhost", [
		{"/", hello_h, []}%,
%		{"/echo/:key", echo_h, []},
%		{"/delay_hello", delay_hello_h, 1200},
%		{"/long_polling", long_polling_h, []},
%		{"/loop_handler_abort", loop_handler_abort_h, []},
%		{"/resp/:key[/:arg]", resp_h, []}
	]}
].

%% Starting HTTP/3 for "https" URIs.

alpn(Config) ->
	doc("Successful ALPN negotiation. (RFC9114 3.1)"),
	{ok, Conn} = quicer:connect("localhost", config(port, Config),
		#{alpn => ["h3"], verify => none}, 5000),
	{ok, <<"h3">>} = quicer:getopt(Conn, param_tls_negotiated_alpn, quic_tls),
	%% To make sure the connection is fully established we wait
	%% to receive the SETTINGS frame on the control stream.
	{ok, _ControlRef, _Settings} = do_wait_settings(Conn),
	ok.

alpn_error(Config) ->
	doc("Failed ALPN negotiation using the 'h2' token. (RFC9114 3.1)"),
	{error, transport_down, #{status := alpn_neg_failure}}
		= quicer:connect("localhost", config(port, Config),
			#{alpn => ["h2"], verify => none}, 5000),
	ok.

%% @todo 3.2. Connection Establishment
%% After the QUIC connection is established, a SETTINGS frame MUST be sent by each endpoint as the initial frame of their respective HTTP control stream.

%% @todo 3.3. Connection Reuse
%% Servers are encouraged to maintain open HTTP/3 connections for as long as
%possible but are permitted to terminate idle connections if necessary. When
%either endpoint chooses to close the HTTP/3 connection, the terminating
%endpoint SHOULD first send a GOAWAY frame (Section 5.2) so that both endpoints
%can reliably determine whether previously sent frames have been processed and
%gracefully complete or terminate any necessary remaining tasks.

%% Frame format.

req_stream(Config) ->
	doc("Complete lifecycle of a request stream. (RFC9114 4.1)"),
	{ok, Conn} = quicer:connect("localhost", config(port, Config),
		#{alpn => ["h3"], verify => none}, 5000),
	%% To make sure the connection is fully established we wait
	%% to receive the SETTINGS frame on the control stream.
	{ok, ControlRef, _Settings} = do_wait_settings(Conn),
	%% Send a request on a request stream.
	{ok, StreamRef} = quicer:start_stream(Conn, #{}),
	{ok, EncodedRequest, _EncData, _EncSt} = cow_qpack:encode_field_section([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>},
		{<<"content-length">>, <<"0">>}
	], 0, cow_qpack:init()),
	{ok, _} = quicer:send(StreamRef, [
		<<1>>, %% HEADERS frame.
		cow_http3:encode_int(iolist_size(EncodedRequest)),
		EncodedRequest
	]),
	ok = do_async_stream_shutdown(StreamRef),
	%% Receive the response.
	{ok, Data} = do_receive_data(StreamRef),
	{HLenEnc, HLenBits} = do_guess_int_encoding(Data),
	<<
		1, %% HEADERS frame.
		HLenEnc:2, HLen:HLenBits,
		EncodedResponse:HLen/bytes,
		Rest/bits
	>> = Data,
	{ok, DecodedResponse, _DecData, _DecSt}
		= cow_qpack:decode_field_section(EncodedResponse, 0, cow_qpack:init()),
	#{
		<<":status">> := <<"200">>,
		<<"content-length">> := BodyLen
	} = maps:from_list(DecodedResponse),
	{DLenEnc, DLenBits} = do_guess_int_encoding(Data),
	<<
		0, %% DATA frame.
		DLenEnc:2, DLen:DLenBits,
		Body:DLen/bytes
	>> = Rest,
	<<"Hello world!">> = Body,
	BodyLen = integer_to_binary(byte_size(Body)),
	ok = do_wait_peer_send_shutdown(StreamRef),
	ok = do_wait_stream_closed(StreamRef).

%% @todo Same test as above but with content-length unset?

req_stream_two_requests(Config) ->
	doc("Receipt of multiple requests on a single stream must "
		"be rejected with an H3_MESSAGE_ERROR stream error. "
		"(RFC9114 4.1, RFC9114 4.1.2)"),
	{ok, Conn} = quicer:connect("localhost", config(port, Config),
		#{alpn => ["h3"], verify => none}, 5000),
	%% To make sure the connection is fully established we wait
	%% to receive the SETTINGS frame on the control stream.
	{ok, ControlRef, _Settings} = do_wait_settings(Conn),
	%% Send two requests on a request stream.
	{ok, StreamRef} = quicer:start_stream(Conn, #{}),
	{ok, EncodedRequest1, _EncData1, EncSt0} = cow_qpack:encode_field_section([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>},
		{<<"content-length">>, <<"0">>}
	], 0, cow_qpack:init()),
	{ok, EncodedRequest2, _EncData2, _EncSt} = cow_qpack:encode_field_section([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>},
		{<<"content-length">>, <<"0">>}
	], 0, EncSt0),
	{ok, _} = quicer:send(StreamRef, [
		<<1>>, %% HEADERS frame.
		cow_http3:encode_int(iolist_size(EncodedRequest1)),
		EncodedRequest1,
		<<1>>, %% HEADERS frame.
		cow_http3:encode_int(iolist_size(EncodedRequest2)),
		EncodedRequest2
	]),
	%% The stream should have been aborted.
	#{reason := h3_message_error} = do_wait_stream_aborted(StreamRef),
	ok.

req_stream_two_requests_sequential(Config) ->
	doc("Receipt of multiple requests on a single stream must "
		"be rejected with an H3_MESSAGE_ERROR stream error. "
		"(RFC9114 4.1, RFC9114 4.1.2)"),
	{ok, Conn} = quicer:connect("localhost", config(port, Config),
		#{alpn => ["h3"], verify => none}, 5000),
	%% To make sure the connection is fully established we wait
	%% to receive the SETTINGS frame on the control stream.
	{ok, ControlRef, _Settings} = do_wait_settings(Conn),
	%% Send a first request.
	{ok, StreamRef} = quicer:start_stream(Conn, #{}),
	{ok, EncodedRequest1, _EncData1, EncSt0} = cow_qpack:encode_field_section([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>},
		{<<"content-length">>, <<"0">>}
	], 0, cow_qpack:init()),
	{ok, _} = quicer:send(StreamRef, [
		<<1>>, %% HEADERS frame.
		cow_http3:encode_int(iolist_size(EncodedRequest1)),
		EncodedRequest1
	]),
	%% Receive the response.
	{ok, Data} = do_receive_data(StreamRef),
	{HLenEnc, HLenBits} = do_guess_int_encoding(Data),
	<<
		1, %% HEADERS frame.
		HLenEnc:2, HLen:HLenBits,
		EncodedResponse:HLen/bytes,
		Rest/bits
	>> = Data,
	{ok, DecodedResponse, _DecData, _DecSt}
		= cow_qpack:decode_field_section(EncodedResponse, 0, cow_qpack:init()),
	#{
		<<":status">> := <<"200">>,
		<<"content-length">> := BodyLen
	} = maps:from_list(DecodedResponse),
	{DLenEnc, DLenBits} = do_guess_int_encoding(Data),
	<<
		0, %% DATA frame.
		DLenEnc:2, DLen:DLenBits,
		Body:DLen/bytes
	>> = Rest,
	<<"Hello world!">> = Body,
	BodyLen = integer_to_binary(byte_size(Body)),
	ok = do_wait_peer_send_shutdown(StreamRef),
	%% Send a second request.
	{ok, EncodedRequest2, _EncData2, _EncSt} = cow_qpack:encode_field_section([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>},
		{<<"content-length">>, <<"0">>}
	], 0, EncSt0),
	{ok, _} = quicer:send(StreamRef, [
		<<1>>, %% HEADERS frame.
		cow_http3:encode_int(iolist_size(EncodedRequest2)),
		EncodedRequest2
	]),
	%% The stream should have been aborted.
	#{reason := h3_message_error} = do_wait_stream_aborted(StreamRef),
	ok.

headers_then_trailers(Config) ->
	doc("Receipt of HEADERS followed by trailer HEADERS must be accepted. (RFC9114 4.1)"),
	#{conn := Conn} = do_connect(Config),
	{ok, StreamRef} = quicer:start_stream(Conn, #{}),
	{ok, EncodedHeaders, _EncData1, EncSt0} = cow_qpack:encode_field_section([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>},
		{<<"content-length">>, <<"0">>}
	], 0, cow_qpack:init()),
	{ok, EncodedTrailers, _EncData2, _EncSt} = cow_qpack:encode_field_section([
		{<<"content-type">>, <<"text/plain">>}
	], 0, EncSt0),
	{ok, _} = quicer:send(StreamRef, [
		<<1>>, %% HEADERS frame.
		cow_http3:encode_int(iolist_size(EncodedHeaders)),
		EncodedHeaders,
		<<1>>, %% HEADERS frame for trailers.
		cow_http3:encode_int(iolist_size(EncodedTrailers)),
		EncodedTrailers
	]),
	ok = do_async_stream_shutdown(StreamRef),
	#{
		headers := #{<<":status">> := <<"200">>},
		body := <<"Hello world!">>
	} = do_receive_response(StreamRef),
	ok.

headers_then_data_then_trailers(Config) ->
	doc("Receipt of HEADERS followed by DATA followed by trailer HEADERS "
		"must be accepted. (RFC9114 4.1)"),
	#{conn := Conn} = do_connect(Config),
	{ok, StreamRef} = quicer:start_stream(Conn, #{}),
	{ok, EncodedHeaders, _EncData1, EncSt0} = cow_qpack:encode_field_section([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>},
		{<<"content-length">>, <<"13">>}
	], 0, cow_qpack:init()),
	{ok, EncodedTrailers, _EncData2, _EncSt} = cow_qpack:encode_field_section([
		{<<"content-type">>, <<"text/plain">>}
	], 0, EncSt0),
	{ok, _} = quicer:send(StreamRef, [
		<<1>>, %% HEADERS frame.
		cow_http3:encode_int(iolist_size(EncodedHeaders)),
		EncodedHeaders,
		<<0>>, %% DATA frame.
		cow_http3:encode_int(13),
		<<"Hello server!">>,
		<<1>>, %% HEADERS frame for trailers.
		cow_http3:encode_int(iolist_size(EncodedTrailers)),
		EncodedTrailers
	]),
	ok = do_async_stream_shutdown(StreamRef),
	#{
		headers := #{<<":status">> := <<"200">>},
		body := <<"Hello world!">>
	} = do_receive_response(StreamRef),
	ok.

data_then_headers(Config) ->
	doc("Receipt of DATA before HEADERS must be rejected "
		"with an H3_FRAME_UNEXPECTED connection error. (RFC9114 4.1)"),
	#{conn := Conn} = do_connect(Config),
	{ok, StreamRef} = quicer:start_stream(Conn, #{}),
	{ok, EncodedHeaders, _EncData1, _EncSt} = cow_qpack:encode_field_section([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>},
		{<<"content-length">>, <<"13">>}
	], 0, cow_qpack:init()),
	{ok, _} = quicer:send(StreamRef, [
		<<0>>, %% DATA frame.
		cow_http3:encode_int(13),
		<<"Hello server!">>,
		<<1>>, %% HEADERS frame.
		cow_http3:encode_int(iolist_size(EncodedHeaders)),
		EncodedHeaders
	]),
	ok = do_async_stream_shutdown(StreamRef),
	%% The connection should have been closed.
	#{reason := h3_frame_unexpected} = do_wait_connection_closed(Conn),
	ok.

headers_then_trailers_then_data(Config) ->
	doc("Receipt of DATA after trailer HEADERS must be rejected "
		"with an H3_FRAME_UNEXPECTED connection error. (RFC9114 4.1)"),
	#{conn := Conn} = do_connect(Config),
	{ok, StreamRef} = quicer:start_stream(Conn, #{}),
	{ok, EncodedHeaders, _EncData1, EncSt0} = cow_qpack:encode_field_section([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>},
		{<<"content-length">>, <<"13">>}
	], 0, cow_qpack:init()),
	{ok, EncodedTrailers, _EncData2, _EncSt} = cow_qpack:encode_field_section([
		{<<"content-type">>, <<"text/plain">>}
	], 0, EncSt0),
	{ok, _} = quicer:send(StreamRef, [
		<<1>>, %% HEADERS frame.
		cow_http3:encode_int(iolist_size(EncodedHeaders)),
		EncodedHeaders,
		<<1>>, %% HEADERS frame for trailers.
		cow_http3:encode_int(iolist_size(EncodedTrailers)),
		EncodedTrailers,
		<<0>>, %% DATA frame.
		cow_http3:encode_int(13),
		<<"Hello server!">>
	]),
	ok = do_async_stream_shutdown(StreamRef),
	%% The connection should have been closed.
	#{reason := h3_frame_unexpected} = do_wait_connection_closed(Conn),
	ok.

headers_then_data_then_trailers_then_data(Config) ->
	doc("Receipt of DATA after trailer HEADERS must be rejected "
		"with an H3_FRAME_UNEXPECTED connection error. (RFC9114 4.1)"),
	#{conn := Conn} = do_connect(Config),
	{ok, StreamRef} = quicer:start_stream(Conn, #{}),
	{ok, EncodedHeaders, _EncData1, EncSt0} = cow_qpack:encode_field_section([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>},
		{<<"content-length">>, <<"13">>}
	], 0, cow_qpack:init()),
	{ok, EncodedTrailers, _EncData2, _EncSt} = cow_qpack:encode_field_section([
		{<<"content-type">>, <<"text/plain">>}
	], 0, EncSt0),
	{ok, _} = quicer:send(StreamRef, [
		<<1>>, %% HEADERS frame.
		cow_http3:encode_int(iolist_size(EncodedHeaders)),
		EncodedHeaders,
		<<0>>, %% DATA frame.
		cow_http3:encode_int(13),
		<<"Hello server!">>,
		<<1>>, %% HEADERS frame for trailers.
		cow_http3:encode_int(iolist_size(EncodedTrailers)),
		EncodedTrailers,
		<<0>>, %% DATA frame.
		cow_http3:encode_int(13),
		<<"Hello server!">>
	]),
	ok = do_async_stream_shutdown(StreamRef),
	%% The connection should have been closed.
	#{reason := h3_frame_unexpected} = do_wait_connection_closed(Conn),
	ok.

headers_then_data_then_trailers_then_trailers(Config) ->
	doc("Receipt of DATA after trailer HEADERS must be rejected "
		"with an H3_FRAME_UNEXPECTED connection error. (RFC9114 4.1)"),
	#{conn := Conn} = do_connect(Config),
	{ok, StreamRef} = quicer:start_stream(Conn, #{}),
	{ok, EncodedHeaders, _EncData1, EncSt0} = cow_qpack:encode_field_section([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>},
		{<<"content-length">>, <<"13">>}
	], 0, cow_qpack:init()),
	{ok, EncodedTrailers1, _EncData2, EncSt1} = cow_qpack:encode_field_section([
		{<<"content-type">>, <<"text/plain">>}
	], 0, EncSt0),
	{ok, EncodedTrailers2, _EncData3, _EncSt} = cow_qpack:encode_field_section([
		{<<"content-type">>, <<"text/plain">>}
	], 0, EncSt1),
	{ok, _} = quicer:send(StreamRef, [
		<<1>>, %% HEADERS frame.
		cow_http3:encode_int(iolist_size(EncodedHeaders)),
		EncodedHeaders,
		<<0>>, %% DATA frame.
		cow_http3:encode_int(13),
		<<"Hello server!">>,
		<<1>>, %% HEADERS frame for trailers.
		cow_http3:encode_int(iolist_size(EncodedTrailers1)),
		EncodedTrailers1,
		<<1>>, %% HEADERS frame for trailers.
		cow_http3:encode_int(iolist_size(EncodedTrailers2)),
		EncodedTrailers2
	]),
	ok = do_async_stream_shutdown(StreamRef),
	%% The connection should have been closed.
	#{reason := h3_frame_unexpected} = do_wait_connection_closed(Conn),
	ok.

unknown_then_headers(Config) ->
	doc("Receipt of unknown frame followed by HEADERS "
		"must be accepted. (RFC9114 4.1, RFC9114 9)"),
	unknown_then_headers(Config, do_unknown_frame_type(),
		rand:bytes(rand:uniform(4096))).

unknown_then_headers(Config, Type, Bytes) ->
	#{conn := Conn} = do_connect(Config),
	{ok, StreamRef} = quicer:start_stream(Conn, #{}),
	{ok, EncodedHeaders, _EncData, _EncSt} = cow_qpack:encode_field_section([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>},
		{<<"content-length">>, <<"0">>}
	], 0, cow_qpack:init()),
	{ok, _} = quicer:send(StreamRef, [
		cow_http3:encode_int(Type), %% Unknown frame.
		cow_http3:encode_int(iolist_size(Bytes)),
		Bytes,
		<<1>>, %% HEADERS frame.
		cow_http3:encode_int(iolist_size(EncodedHeaders)),
		EncodedHeaders
	]),
	ok = do_async_stream_shutdown(StreamRef),
	#{
		headers := #{<<":status">> := <<"200">>},
		body := <<"Hello world!">>
	} = do_receive_response(StreamRef),
	ok.

headers_then_unknown(Config) ->
	doc("Receipt of HEADERS followed by unknown frame "
		"must be accepted. (RFC9114 4.1, RFC9114 9)"),
	headers_then_unknown(Config, do_unknown_frame_type(),
		rand:bytes(rand:uniform(4096))).

headers_then_unknown(Config, Type, Bytes) ->
	#{conn := Conn} = do_connect(Config),
	{ok, StreamRef} = quicer:start_stream(Conn, #{}),
	{ok, EncodedHeaders, _EncData, _EncSt} = cow_qpack:encode_field_section([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>},
		{<<"content-length">>, <<"0">>}
	], 0, cow_qpack:init()),
	{ok, _} = quicer:send(StreamRef, [
		<<1>>, %% HEADERS frame.
		cow_http3:encode_int(iolist_size(EncodedHeaders)),
		EncodedHeaders,
		cow_http3:encode_int(Type), %% Unknown frame.
		cow_http3:encode_int(iolist_size(Bytes)),
		Bytes
	]),
	ok = do_async_stream_shutdown(StreamRef),
	#{
		headers := #{<<":status">> := <<"200">>},
		body := <<"Hello world!">>
	} = do_receive_response(StreamRef),
	ok.

headers_then_data_then_unknown(Config) ->
	doc("Receipt of HEADERS followed by DATA followed by unknown frame "
		"must be accepted. (RFC9114 4.1, RFC9114 9)"),
	headers_then_data_then_unknown(Config, do_unknown_frame_type(),
		rand:bytes(rand:uniform(4096))).

headers_then_data_then_unknown(Config, Type, Bytes) ->
	#{conn := Conn} = do_connect(Config),
	{ok, StreamRef} = quicer:start_stream(Conn, #{}),
	{ok, EncodedHeaders, _EncData, _EncSt} = cow_qpack:encode_field_section([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>},
		{<<"content-length">>, <<"13">>}
	], 0, cow_qpack:init()),
	{ok, _} = quicer:send(StreamRef, [
		<<1>>, %% HEADERS frame.
		cow_http3:encode_int(iolist_size(EncodedHeaders)),
		EncodedHeaders,
		<<0>>, %% DATA frame.
		cow_http3:encode_int(13),
		<<"Hello server!">>,
		cow_http3:encode_int(Type), %% Unknown frame.
		cow_http3:encode_int(iolist_size(Bytes)),
		Bytes
	]),
	ok = do_async_stream_shutdown(StreamRef),
	#{
		headers := #{<<":status">> := <<"200">>},
		body := <<"Hello world!">>
	} = do_receive_response(StreamRef),
	ok.

headers_then_trailers_then_unknown(Config) ->
	doc("Receipt of HEADERS followed by trailer HEADERS followed by unknown frame "
		"must be accepted. (RFC9114 4.1, RFC9114 9)"),
	headers_then_data_then_unknown(Config, do_unknown_frame_type(),
		rand:bytes(rand:uniform(4096))).

headers_then_trailers_then_unknown(Config, Type, Bytes) ->
	#{conn := Conn} = do_connect(Config),
	{ok, StreamRef} = quicer:start_stream(Conn, #{}),
	{ok, EncodedHeaders, _EncData, EncSt0} = cow_qpack:encode_field_section([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>},
		{<<"content-length">>, <<"13">>}
	], 0, cow_qpack:init()),
	{ok, EncodedTrailers, _EncData2, _EncSt} = cow_qpack:encode_field_section([
		{<<"content-type">>, <<"text/plain">>}
	], 0, EncSt0),
	{ok, _} = quicer:send(StreamRef, [
		<<1>>, %% HEADERS frame.
		cow_http3:encode_int(iolist_size(EncodedHeaders)),
		EncodedHeaders,
		<<1>>, %% HEADERS frame for trailers.
		cow_http3:encode_int(iolist_size(EncodedTrailers)),
		EncodedTrailers,
		cow_http3:encode_int(Type), %% Unknown frame.
		cow_http3:encode_int(iolist_size(Bytes)),
		Bytes
	]),
	ok = do_async_stream_shutdown(StreamRef),
	#{
		headers := #{<<":status">> := <<"200">>},
		body := <<"Hello world!">>
	} = do_receive_response(StreamRef),
	ok.

headers_then_data_then_unknown_then_trailers(Config) ->
	doc("Receipt of HEADERS followed by DATA followed by "
		"unknown frame followed by trailer HEADERS "
		"must be accepted. (RFC9114 4.1, RFC9114 9)"),
	headers_then_data_then_unknown_then_trailers(Config,
		do_unknown_frame_type(), rand:bytes(rand:uniform(4096))).

headers_then_data_then_unknown_then_trailers(Config, Type, Bytes) ->
	#{conn := Conn} = do_connect(Config),
	{ok, StreamRef} = quicer:start_stream(Conn, #{}),
	{ok, EncodedHeaders, _EncData, EncSt0} = cow_qpack:encode_field_section([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>},
		{<<"content-length">>, <<"13">>}
	], 0, cow_qpack:init()),
	{ok, EncodedTrailers, _EncData2, _EncSt} = cow_qpack:encode_field_section([
		{<<"content-type">>, <<"text/plain">>}
	], 0, EncSt0),
	{ok, _} = quicer:send(StreamRef, [
		<<1>>, %% HEADERS frame.
		cow_http3:encode_int(iolist_size(EncodedHeaders)),
		EncodedHeaders,
		<<0>>, %% DATA frame.
		cow_http3:encode_int(13),
		<<"Hello server!">>,
		cow_http3:encode_int(Type), %% Unknown frame.
		cow_http3:encode_int(iolist_size(Bytes)),
		Bytes,
		<<1>>, %% HEADERS frame for trailers.
		cow_http3:encode_int(iolist_size(EncodedTrailers)),
		EncodedTrailers
	]),
	ok = do_async_stream_shutdown(StreamRef),
	#{
		headers := #{<<":status">> := <<"200">>},
		body := <<"Hello world!">>
	} = do_receive_response(StreamRef),
	ok.

headers_then_data_then_unknown_then_data(Config) ->
	doc("Receipt of HEADERS followed by DATA followed by "
		"unknown frame followed by DATA "
		"must be accepted. (RFC9114 4.1, RFC9114 9)"),
	headers_then_data_then_unknown_then_data(Config,
		do_unknown_frame_type(), rand:bytes(rand:uniform(4096))).

headers_then_data_then_unknown_then_data(Config, Type, Bytes) ->
	#{conn := Conn} = do_connect(Config),
	{ok, StreamRef} = quicer:start_stream(Conn, #{}),
	{ok, EncodedHeaders, _EncData, _EncSt} = cow_qpack:encode_field_section([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>},
		{<<"content-length">>, <<"13">>}
	], 0, cow_qpack:init()),
	{ok, _} = quicer:send(StreamRef, [
		<<1>>, %% HEADERS frame.
		cow_http3:encode_int(iolist_size(EncodedHeaders)),
		EncodedHeaders,
		<<0>>, %% DATA frame.
		cow_http3:encode_int(6),
		<<"Hello ">>,
		cow_http3:encode_int(Type), %% Unknown frame.
		cow_http3:encode_int(iolist_size(Bytes)),
		Bytes,
		<<0>>, %% DATA frame.
		cow_http3:encode_int(7),
		<<"server!">>
	]),
	ok = do_async_stream_shutdown(StreamRef),
	#{
		headers := #{<<":status">> := <<"200">>},
		body := <<"Hello world!">>
	} = do_receive_response(StreamRef),
	ok.

headers_then_data_then_trailers_then_unknown(Config) ->
	doc("Receipt of HEADERS followed by DATA followed by "
		"trailer HEADERS followed by unknown frame "
		"must be accepted. (RFC9114 4.1, RFC9114 9)"),
	headers_then_data_then_trailers_then_unknown(Config,
		do_unknown_frame_type(), rand:bytes(rand:uniform(4096))).

headers_then_data_then_trailers_then_unknown(Config, Type, Bytes) ->
	#{conn := Conn} = do_connect(Config),
	{ok, StreamRef} = quicer:start_stream(Conn, #{}),
	{ok, EncodedHeaders, _EncData, EncSt0} = cow_qpack:encode_field_section([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>},
		{<<"content-length">>, <<"13">>}
	], 0, cow_qpack:init()),
	{ok, EncodedTrailers, _EncData2, _EncSt} = cow_qpack:encode_field_section([
		{<<"content-type">>, <<"text/plain">>}
	], 0, EncSt0),
	{ok, _} = quicer:send(StreamRef, [
		<<1>>, %% HEADERS frame.
		cow_http3:encode_int(iolist_size(EncodedHeaders)),
		EncodedHeaders,
		<<0>>, %% DATA frame.
		cow_http3:encode_int(13),
		<<"Hello server!">>,
		<<1>>, %% HEADERS frame for trailers.
		cow_http3:encode_int(iolist_size(EncodedTrailers)),
		EncodedTrailers,
		cow_http3:encode_int(Type), %% Unknown frame.
		cow_http3:encode_int(iolist_size(Bytes)),
		Bytes
	]),
	ok = do_async_stream_shutdown(StreamRef),
	#{
		headers := #{<<":status">> := <<"200">>},
		body := <<"Hello world!">>
	} = do_receive_response(StreamRef),
	ok.

do_unknown_frame_type() ->
	Type = rand:uniform(4611686018427387904) - 1,
	%% Retry if we get a value that's specified.
	case lists:member(Type, [
		16#0, 16#1, 16#3, 16#4, 16#5, 16#7, 16#d, %% HTTP/3 core frame types.
		16#2, 16#6, 16#8, 16#9 %% HTTP/3 reserved frame types that must be rejected.
	]) of
		true -> do_unknown_frame_type();
		false -> Type
	end.

reserved_then_headers(Config) ->
	doc("Receipt of reserved frame followed by HEADERS "
		"must be accepted when the reserved frame type is "
		"of the format 0x1f * N + 0x21. (RFC9114 4.1, RFC9114 7.2.8)"),
	unknown_then_headers(Config, do_reserved_frame_type(),
		rand:bytes(rand:uniform(4096))).

headers_then_reserved(Config) ->
	doc("Receipt of HEADERS followed by reserved frame "
		"must be accepted when the reserved frame type is "
		"of the format 0x1f * N + 0x21. (RFC9114 4.1, RFC9114 7.2.8)"),
	headers_then_unknown(Config, do_reserved_frame_type(),
		rand:bytes(rand:uniform(4096))).

headers_then_data_then_reserved(Config) ->
	doc("Receipt of HEADERS followed by DATA followed by reserved frame "
		"must be accepted when the reserved frame type is "
		"of the format 0x1f * N + 0x21. (RFC9114 4.1, RFC9114 7.2.8)"),
	headers_then_data_then_unknown(Config, do_reserved_frame_type(),
		rand:bytes(rand:uniform(4096))).

headers_then_trailers_then_reserved(Config) ->
	doc("Receipt of HEADERS followed by trailer HEADERS followed by reserved frame "
		"must be accepted when the reserved frame type is "
		"of the format 0x1f * N + 0x21. (RFC9114 4.1, RFC9114 7.2.8)"),
	headers_then_trailers_then_unknown(Config, do_reserved_frame_type(),
		rand:bytes(rand:uniform(4096))).

headers_then_data_then_reserved_then_trailers(Config) ->
	doc("Receipt of HEADERS followed by DATA followed by "
		"reserved frame followed by trailer HEADERS "
		"must be accepted when the reserved frame type is "
		"of the format 0x1f * N + 0x21. (RFC9114 4.1, RFC9114 7.2.8)"),
	headers_then_data_then_unknown_then_trailers(Config,
		do_reserved_frame_type(), rand:bytes(rand:uniform(4096))).

headers_then_data_then_reserved_then_data(Config) ->
	doc("Receipt of HEADERS followed by DATA followed by "
		"reserved frame followed by DATA "
		"must be accepted when the reserved frame type is "
		"of the format 0x1f * N + 0x21. (RFC9114 4.1, RFC9114 7.2.8)"),
	headers_then_data_then_unknown_then_data(Config,
		do_reserved_frame_type(), rand:bytes(rand:uniform(4096))).

headers_then_data_then_trailers_then_reserved(Config) ->
	doc("Receipt of HEADERS followed by DATA followed by "
		"trailer HEADERS followed by reserved frame "
		"must be accepted when the reserved frame type is "
		"of the format 0x1f * N + 0x21. (RFC9114 4.1, RFC9114 7.2.8)"),
	headers_then_data_then_trailers_then_unknown(Config,
		do_reserved_frame_type(), rand:bytes(rand:uniform(4096))).

do_reserved_frame_type() ->
	16#1f * (rand:uniform(148764065110560900) - 1) + 16#21.

reject_transfer_encoding_header_with_body(Config) ->
	doc("Requests containing a transfer-encoding header must be rejected "
		"with an H3_MESSAGE_ERROR stream error. (RFC9114 4.1, RFC9114 4.1.2, RFC9114 4.2)"),
	#{conn := Conn} = do_connect(Config),
	{ok, StreamRef} = quicer:start_stream(Conn, #{}),
	{ok, EncodedHeaders, _EncData1, _EncSt0} = cow_qpack:encode_field_section([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>},
		{<<"transfer-encoding">>, <<"chunked">>}
	], 0, cow_qpack:init()),
	{ok, _} = quicer:send(StreamRef, [
		<<1>>, %% HEADERS frame.
		cow_http3:encode_int(iolist_size(EncodedHeaders)),
		EncodedHeaders,
		<<0>>, %% DATA frame.
		cow_http3:encode_int(24),
		<<"13\r\nHello server!\r\n0\r\n\r\n">>
	]),
	%% The stream should have been aborted.
	#{reason := h3_message_error} = do_wait_stream_aborted(StreamRef),
	ok.

%% 4. Expressing HTTP Semantics in HTTP/3
%% 4.1. HTTP Message Framing

%% An HTTP request/response exchange fully consumes a client-initiated
%bidirectional QUIC stream. After sending a request, a client MUST close the
%stream for sending. Unless using the CONNECT method (see Section 4.4), clients
%MUST NOT make stream closure dependent on receiving a response to their
%request. After sending a final response, the server MUST close the stream for
%sending. At this point, the QUIC stream is fully closed.
%% @todo What to do with clients that DON'T close the stream
%%       for sending after the request is sent?

%% If a client-initiated stream terminates without enough of the HTTP message
%to provide a complete response, the server SHOULD abort its response stream
%with the error code H3_REQUEST_INCOMPLETE.
%% @todo difficult!!

%% When the server does not need to receive the remainder of the request, it
%MAY abort reading the request stream, send a complete response, and cleanly
%close the sending part of the stream. The error code H3_NO_ERROR SHOULD be
%used when requesting that the client stop sending on the request stream.
%% @todo read_body related; h2 has this behavior but there is no corresponding test

%% 4.1.1. Request Cancellation and Rejection

%% When possible, it is RECOMMENDED that servers send an HTTP response with an
%appropriate status code rather than cancelling a request it has already begun
%processing.

%% Implementations SHOULD cancel requests by abruptly terminating any
%directions of a stream that are still open. To do so, an implementation resets
%the sending parts of streams and aborts reading on the receiving parts of
%streams; see Section 2.4 of [QUIC-TRANSPORT].

%% When the server cancels a request without performing any application
%processing, the request is considered "rejected". The server SHOULD abort its
%response stream with the error code H3_REQUEST_REJECTED. In this context,
%"processed" means that some data from the stream was passed to some higher
%layer of software that might have taken some action as a result. The client
%can treat requests rejected by the server as though they had never been sent
%at all, thereby allowing them to be retried later.

%% Servers MUST NOT use the H3_REQUEST_REJECTED error code for requests that
%were partially or fully processed. When a server abandons a response after
%partial processing, it SHOULD abort its response stream with the error code
%H3_REQUEST_CANCELLED.
%% @todo

%% Client SHOULD use the error code H3_REQUEST_CANCELLED to cancel requests.
%Upon receipt of this error code, a server MAY abruptly terminate the response
%using the error code H3_REQUEST_REJECTED if no processing was performed.
%Clients MUST NOT use the H3_REQUEST_REJECTED error code, except when a server
%has requested closure of the request stream with this error code.
%% @todo

%4.1.2. Malformed Requests and Responses
%A malformed request or response is one that is an otherwise valid sequence of
%frames but is invalid due to:
%
%the presence of prohibited fields or pseudo-header fields,
%% @todo reject_response_pseudo_headers
%% @todo reject_unknown_pseudo_headers
%% @todo reject_pseudo_headers_in_trailers

%the absence of mandatory pseudo-header fields,
%invalid values for pseudo-header fields,
%pseudo-header fields after fields,
%% @todo reject_pseudo_headers_after_regular_headers

%an invalid sequence of HTTP messages,
%the inclusion of invalid characters in field names or values.
%
%A request or response that is defined as having content when it contains a
%Content-Length header field (Section 8.6 of [HTTP]) is malformed if the value
%of the Content-Length header field does not equal the sum of the DATA frame
%lengths received. A response that is defined as never having content, even
%when a Content-Length is present, can have a non-zero Content-Length header
%field even though no content is included in DATA frames.
%
%For malformed requests, a server MAY send an HTTP response indicating the
%error prior to closing or resetting the stream.
%% @todo All the malformed tests

headers_reject_uppercase_header_name(Config) ->
	doc("Requests containing uppercase header names must be rejected "
		"with an H3_MESSAGE_ERROR stream error. (RFC9114 4.2, RFC9114 4.1.2)"),
	do_reject_malformed_header(Config,
		{<<"I-AM-GIGANTIC">>, <<"How's the weather up there?">>}
	).

%% 4.2. HTTP Fields
%% An endpoint MUST NOT generate an HTTP/3 field section containing
%connection-specific fields; any message containing connection-specific fields
%MUST be treated as malformed.

reject_connection_header(Config) ->
	doc("Requests containing a connection header must be rejected "
		"with an H3_MESSAGE_ERROR stream error. (RFC9114 4.2, RFC9114 4.1.2)"),
	do_reject_malformed_header(Config,
		{<<"connection">>, <<"close">>}
	).

reject_keep_alive_header(Config) ->
	doc("Requests containing a keep-alive header must be rejected "
		"with an H3_MESSAGE_ERROR stream error. (RFC9114 4.2, RFC9114 4.1.2)"),
	do_reject_malformed_header(Config,
		{<<"keep-alive">>, <<"timeout=5, max=1000">>}
	).

reject_proxy_authenticate_header(Config) ->
	doc("Requests containing a proxy-authenticate header must be rejected "
		"with an H3_MESSAGE_ERROR stream error. (RFC9114 4.2, RFC9114 4.1.2)"),
	do_reject_malformed_header(Config,
		{<<"proxy-authenticate">>, <<"Basic">>}
	).

reject_proxy_authorization_header(Config) ->
	doc("Requests containing a proxy-authorization header must be rejected "
		"with an H3_MESSAGE_ERROR stream error. (RFC9114 4.2, RFC9114 4.1.2)"),
	do_reject_malformed_header(Config,
		{<<"proxy-authorization">>, <<"Basic YWxhZGRpbjpvcGVuc2VzYW1l">>}
	).

reject_transfer_encoding_header(Config) ->
	doc("Requests containing a transfer-encoding header must be rejected "
		"with an H3_MESSAGE_ERROR stream error. (RFC9114 4.2, RFC9114 4.1.2)"),
	do_reject_malformed_header(Config,
		{<<"transfer-encoding">>, <<"chunked">>}
	).

reject_upgrade_header(Config) ->
	doc("Requests containing an upgrade header must be rejected "
		"with an H3_MESSAGE_ERROR stream error. (RFC9114 4.2, RFC9114 4.1.2)"),
	do_reject_malformed_header(Config,
		{<<"upgrade">>, <<"websocket">>}
	).

accept_te_header_value_trailers(Config) ->
	doc("Requests containing a TE header with a value of \"trailers\" "
		"must be accepted. (RFC9114 4.2)"),
	#{conn := Conn} = do_connect(Config),
	{ok, StreamRef} = quicer:start_stream(Conn, #{}),
	{ok, EncodedHeaders, _EncData1, EncSt0} = cow_qpack:encode_field_section([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>},
		{<<"content-length">>, <<"0">>},
		{<<"te">>, <<"trailers">>}
	], 0, cow_qpack:init()),
	{ok, EncodedTrailers, _EncData2, _EncSt} = cow_qpack:encode_field_section([
		{<<"content-type">>, <<"text/plain">>}
	], 0, EncSt0),
	{ok, _} = quicer:send(StreamRef, [
		<<1>>, %% HEADERS frame.
		cow_http3:encode_int(iolist_size(EncodedHeaders)),
		EncodedHeaders,
		<<1>>, %% HEADERS frame for trailers.
		cow_http3:encode_int(iolist_size(EncodedTrailers)),
		EncodedTrailers
	]),
	ok = do_async_stream_shutdown(StreamRef),
	#{
		headers := #{<<":status">> := <<"200">>},
		body := <<"Hello world!">>
	} = do_receive_response(StreamRef),
	ok.

reject_te_header_other_values(Config) ->
	doc("Requests containing a TE header with a value other than \"trailers\" must be rejected "
		"with an H3_MESSAGE_ERROR stream error. (RFC9114 4.2, RFC9114 4.1.2)"),
	do_reject_malformed_header(Config,
		{<<"te">>, <<"trailers, deflate;q=0.5">>}
	).

%% @todo response_dont_send_header_in_connection
%% @todo response_dont_send_connection_header
%% @todo response_dont_send_keep_alive_header
%% @todo response_dont_send_proxy_connection_header
%% @todo response_dont_send_transfer_encoding_header
%% @todo response_dont_send_upgrade_header

%% 4.2.1. Field Compression
%% To allow for better compression efficiency, the Cookie header field
%([COOKIES]) MAY be split into separate field lines, each with one or more
%cookie-pairs, before compression. If a decompressed field section contains
%multiple cookie field lines, these MUST be concatenated into a single byte
%string using the two-byte delimiter of "; " (ASCII 0x3b, 0x20) before being
%passed into a context other than HTTP/2 or HTTP/3, such as an HTTP/1.1
%connection, or a generic HTTP server application.

%% 4.2.2. Header Size Constraints
%% An HTTP/3 implementation MAY impose a limit on the maximum size of the
%message header it will accept on an individual HTTP message. A server that
%receives a larger header section than it is willing to handle can send an HTTP
%431 (Request Header Fields Too Large) status code ([RFC6585]). The size of a
%field list is calculated based on the uncompressed size of fields, including
%the length of the name and value in bytes plus an overhead of 32 bytes for
%each field.
%% If an implementation wishes to advise its peer of this limit, it can be
%conveyed as a number of bytes in the SETTINGS_MAX_FIELD_SECTION_SIZE
%parameter. 

reject_unknown_pseudo_headers(Config) ->
	doc("Requests containing unknown pseudo-headers must be rejected "
		"with an H3_MESSAGE_ERROR stream error. (RFC9114 4.3, RFC9114 4.1.2)"),
	do_reject_malformed_header(Config,
		{<<":upgrade">>, <<"websocket">>}
	).

reject_response_pseudo_headers(Config) ->
	doc("Requests containing response pseudo-headers must be rejected "
		"with an H3_MESSAGE_ERROR stream error. (RFC9114 4.3, RFC9114 4.1.2)"),
	do_reject_malformed_header(Config,
		{<<":status">>, <<"200">>}
	).

reject_pseudo_headers_in_trailers(Config) ->
	doc("Requests containing pseudo-headers in trailers must be rejected "
		"with an H3_MESSAGE_ERROR stream error. (RFC9114 4.3, RFC9114 4.1.2)"),
	#{conn := Conn} = do_connect(Config),
	{ok, StreamRef} = quicer:start_stream(Conn, #{}),
	{ok, EncodedHeaders, _EncData1, EncSt0} = cow_qpack:encode_field_section([
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>},
		{<<"trailer">>, <<"x-checksum">>}
	], 0, cow_qpack:init()),
	{ok, EncodedTrailers, _EncData2, _EncSt} = cow_qpack:encode_field_section([
		{<<"x-checksum">>, <<"md5:4cc909a007407f3706399b6496babec3">>},
		{<<":path">>, <<"/">>}
	], 0, EncSt0),
	{ok, _} = quicer:send(StreamRef, [
		<<1>>, %% HEADERS frame.
		cow_http3:encode_int(iolist_size(EncodedHeaders)),
		EncodedHeaders,
		<<0>>, %% DATA frame.
		cow_http3:encode_int(10000),
		<<0:10000/unit:8>>,
		<<1>>, %% HEADERS frame for trailers.
		cow_http3:encode_int(iolist_size(EncodedTrailers)),
		EncodedTrailers
	]),
	%% The stream should have been aborted.
	#{reason := h3_message_error} = do_wait_stream_aborted(StreamRef),
	ok.

reject_pseudo_headers_after_regular_headers(Config) ->
	doc("Requests containing pseudo-headers after regular headers must be rejected "
		"with an H3_MESSAGE_ERROR stream error. (RFC9114 4.3, RFC9114 4.1.2)"),
	do_reject_malformed_headers(Config, [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"localhost">>},
		{<<"content-length">>, <<"0">>},
		{<<":path">>, <<"/">>}
	]).

reject_userinfo(Config) ->
	doc("An authority containing a userinfo component must be rejected "
		"with an H3_MESSAGE_ERROR stream error. (RFC9114 4.3.1, RFC9114 4.1.2)"),
	do_reject_malformed_headers(Config, [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"http">>},
		{<<":authority">>, <<"user@localhost">>},
		{<<":path">>, <<"/">>}
	]).

%% To ensure that the HTTP/1.1 request line can be reproduced accurately, this
%% pseudo-header field (:authority) MUST be omitted when translating from an
%% HTTP/1.1 request that has a request target in a method-specific form;
%% see Section 7.1 of [HTTP]. 

reject_empty_path(Config) ->
	doc("A request containing an empty path component must be rejected "
		"with an H3_MESSAGE_ERROR stream error. (RFC9114 4.3.1, RFC9114 4.1.2)"),
	do_reject_malformed_headers(Config, [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"http">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<>>}
	]).

reject_missing_pseudo_header_method(Config) ->
	doc("A request without a method component must be rejected "
		"with an H3_MESSAGE_ERROR stream error. (RFC9114 4.3.1, RFC9114 4.1.2)"),
	do_reject_malformed_headers(Config, [
		{<<":scheme">>, <<"http">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>}
	]).

reject_many_pseudo_header_method(Config) ->
	doc("A request containing more than one method component must be rejected "
		"with an H3_MESSAGE_ERROR stream error. (RFC9114 4.3.1, RFC9114 4.1.2)"),
	do_reject_malformed_headers(Config, [
		{<<":method">>, <<"GET">>},
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"http">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>}
	]).

reject_missing_pseudo_header_scheme(Config) ->
	doc("A request without a scheme component must be rejected "
		"with an H3_MESSAGE_ERROR stream error. (RFC9114 4.3.1, RFC9114 4.1.2)"),
	do_reject_malformed_headers(Config, [
		{<<":method">>, <<"GET">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>}
	]).

reject_many_pseudo_header_scheme(Config) ->
	doc("A request containing more than one scheme component must be rejected "
		"with an H3_MESSAGE_ERROR stream error. (RFC9114 4.3.1, RFC9114 4.1.2)"),
	do_reject_malformed_headers(Config, [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"http">>},
		{<<":scheme">>, <<"http">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>}
	]).

reject_missing_pseudo_header_authority(Config) ->
	doc("A request without an authority or host component must be rejected "
		"with an H3_MESSAGE_ERROR stream error. (RFC9114 4.3.1, RFC9114 4.1.2)"),
	do_reject_malformed_headers(Config, [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"http">>},
		{<<":path">>, <<"/">>}
	]).

%% @todo
%accept_host_header_on_missing_pseudo_header_authority(Config) ->
%	doc("A request without an authority but with a host header must be accepted. "
%		"(RFC7540 8.1.2.3, RFC7540 8.1.3)"),
%	{ok, Socket} = do_handshake(Config),
%	%% Send a HEADERS frame with host header and without an :authority pseudo-header.
%	{HeadersBlock, _} = cow_hpack:encode([
%		{<<":method">>, <<"GET">>},
%		{<<":scheme">>, <<"http">>},
%		{<<":path">>, <<"/">>},
%		{<<"host">>, <<"localhost">>}
%	]),
%	ok = gen_tcp:send(Socket, cow_http2:headers(1, fin, HeadersBlock)),
%	%% Receive a 200 response.
%	{ok, << Len:24, 1:8, _:8, _:32 >>} = gen_tcp:recv(Socket, 9, 6000),
%	{ok, RespHeadersBlock} = gen_tcp:recv(Socket, Len, 6000),
%	{RespHeaders, _} = cow_hpack:decode(RespHeadersBlock),
%	{_, <<"200">>} = lists:keyfind(<<":status">>, 1, RespHeaders),
%	ok.

%% @todo
%% If the :scheme pseudo-header field identifies a scheme that has a mandatory
%% authority component (including "http" and "https"), the request MUST contain
%% either an :authority pseudo-header field or a Host header field.
%%  - If both fields are present, they MUST NOT be empty.
%%  - If both fields are present, they MUST contain the same value. 

reject_many_pseudo_header_authority(Config) ->
	doc("A request containing more than one authority component must be rejected "
		"with an H3_MESSAGE_ERROR stream error. (RFC9114 4.3.1, RFC9114 4.1.2)"),
	do_reject_malformed_headers(Config, [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"http">>},
		{<<":authority">>, <<"localhost">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>}
	]).

reject_missing_pseudo_header_path(Config) ->
	doc("A request without a path component must be rejected "
		"with an H3_MESSAGE_ERROR stream error. (RFC9114 4.3.1, RFC9114 4.1.2)"),
	do_reject_malformed_headers(Config, [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"http">>},
		{<<":authority">>, <<"localhost">>}
	]).

reject_many_pseudo_header_path(Config) ->
	doc("A request containing more than one path component must be rejected "
		"with an H3_MESSAGE_ERROR stream error. (RFC9114 4.3.1, RFC9114 4.1.2)"),
	do_reject_malformed_headers(Config, [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"http">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>},
		{<<":path">>, <<"/">>}
	]).














do_reject_malformed_header(Config, Header) ->
	do_reject_malformed_headers(Config, [
		{<<":method">>, <<"GET">>},
		{<<":scheme">>, <<"https">>},
		{<<":authority">>, <<"localhost">>},
		{<<":path">>, <<"/">>},
		Header
	]).

do_reject_malformed_headers(Config, Headers) ->
	#{conn := Conn} = do_connect(Config),
	{ok, StreamRef} = quicer:start_stream(Conn, #{}),
	{ok, EncodedHeaders, _EncData1, _EncSt0}
		= cow_qpack:encode_field_section(Headers, 0, cow_qpack:init()),
	{ok, _} = quicer:send(StreamRef, [
		<<1>>, %% HEADERS frame.
		cow_http3:encode_int(iolist_size(EncodedHeaders)),
		EncodedHeaders
	]),
	%% The stream should have been aborted.
	#{reason := h3_message_error} = do_wait_stream_aborted(StreamRef),
	ok.


























%% Helper functions.

do_connect(Config) ->
	{ok, Conn} = quicer:connect("localhost", config(port, Config),
		#{alpn => ["h3"], verify => none}, 5000),
	%% To make sure the connection is fully established we wait
	%% to receive the SETTINGS frame on the control stream.
	{ok, ControlRef, _Settings} = do_wait_settings(Conn),
	#{
		conn => Conn,
		control => ControlRef
	}.

do_wait_settings(Conn) ->
	{ok, Conn} = quicer:async_accept_stream(Conn, []),
	receive
		{quic, new_stream, StreamRef, #{flags := Flags}} ->
			true = quicer:is_unidirectional(Flags),
			receive {quic, <<
				0, %% Control stream.
				4, 0 %% Empty SETTINGS frame.
			>>, StreamRef, _} ->
				{ok, StreamRef, #{}}
			after 5000 ->
				{error, timeout}
			end
	after 5000 ->
		{error, timeout}
	end.

do_receive_data(StreamRef) ->
	receive
		{quic, Data, StreamRef, _Flags} when is_binary(Data) ->
			{ok, Data}
	after 5000 ->
		{error, timeout}
	end.

do_guess_int_encoding(Data) ->
	SizeWithLen = byte_size(Data) - 1,
	if
		SizeWithLen < 64 + 1 ->
			{0, 6};
		SizeWithLen < 16384 + 2 ->
			{1, 14};
		SizeWithLen < 1073741824 + 4 ->
			{2, 30};
		SizeWithLen < 4611686018427387904 + 8 ->
			{3, 62}
	end.

do_async_stream_shutdown(StreamRef) ->
	quicer:async_shutdown_stream(StreamRef, ?QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0),
	receive
		{quic, send_shutdown_complete, StreamRef, true} ->
			ok
	after 5000 ->
		{error, timeout}
	end.

do_wait_peer_send_shutdown(StreamRef) ->
	receive
		{quic, peer_send_shutdown, StreamRef, undefined} ->
			ok
	after 5000 ->
		{error, timeout}
	end.

do_wait_stream_aborted(StreamRef) ->
	receive
		{quic, peer_send_aborted, StreamRef, Code} ->
			Reason = cow_http3:code_to_error(Code),
			#{reason => Reason};
		{quic, peer_receive_aborted, StreamRef, Code} ->
			Reason = cow_http3:code_to_error(Code),
			#{reason => Reason}
	after 5000 ->
		{error, timeout}
	end.

do_wait_stream_closed(StreamRef) ->
	receive
		{quic, stream_closed, StreamRef, #{error := Error, is_conn_shutdown := false}} ->
			0 = Error,
			ok
	after 5000 ->
		{error, timeout}
	end.

do_receive_response(StreamRef) ->
	{ok, Data} = do_receive_data(StreamRef),
	{HLenEnc, HLenBits} = do_guess_int_encoding(Data),
	<<
		1, %% HEADERS frame.
		HLenEnc:2, HLen:HLenBits,
		EncodedResponse:HLen/bytes,
		Rest/bits
	>> = Data,
	{ok, DecodedResponse, _DecData, _DecSt}
		= cow_qpack:decode_field_section(EncodedResponse, 0, cow_qpack:init()),
	Headers = maps:from_list(DecodedResponse),
	#{<<"content-length">> := BodyLen} = Headers,
	{DLenEnc, DLenBits} = do_guess_int_encoding(Data),
	<<
		0, %% DATA frame.
		DLenEnc:2, DLen:DLenBits,
		Body:DLen/bytes
	>> = Rest,
	BodyLen = integer_to_binary(byte_size(Body)),
	ok = do_wait_peer_send_shutdown(StreamRef),
	ok = do_wait_stream_closed(StreamRef),
	#{
		headers => Headers,
		body => Body
	}.

do_wait_connection_closed(Conn) ->
	receive
		{quic, shutdown, Conn, {unknown_quic_status, Code}} ->
			Reason = cow_http3:code_to_error(Code),
			#{reason => Reason}
	after 5000 ->
		{error, timeout}
	end.





%% 4.3.2. Response Pseudo-Header Fields
%% For responses, a single ":status" pseudo-header field is defined that
%carries the HTTP status code; see Section 15 of [HTTP]. This pseudo-header
%field MUST be included in all responses; otherwise, the response is malformed
%(see Section 4.1.2).
%% HTTP/3 does not define a way to carry the version or reason phrase that is
%included in an HTTP/1.1 status line. HTTP/3 responses implicitly have a
%protocol version of "3.0".

%% 4.4. The CONNECT Method
%% A CONNECT request MUST be constructed as follows:
%%The :method pseudo-header field is set to "CONNECT"
%%The :scheme and :path pseudo-header fields are omitted
%%The :authority pseudo-header field contains the host and port to connect to
%(equivalent to the authority-form of the request-target of CONNECT requests;
%see Section 7.1 of [HTTP]).
%% The request stream remains open at the end of the request to carry the data
%to be transferred. A CONNECT request that does not conform to these
%restrictions is malformed.
%%
%% Once the CONNECT method has completed, only DATA frames are permitted to be
%sent on the stream. Extension frames MAY be used if specifically permitted by
%the definition of the extension. Receipt of any other known frame type MUST be
%treated as a connection error of type H3_FRAME_UNEXPECTED.%% @todo + review
%how it should work beyond the handling of the CONNECT request

%% 4.5. HTTP Upgrade
%% HTTP/3 does not support the HTTP Upgrade mechanism (Section 7.8 of [HTTP])
%or the 101 (Switching Protocols) informational status code (Section 15.2.2 of
%[HTTP]).

%% 4.6. Server Push
%% The push ID space begins at zero and ends at a maximum value set by the
%MAX_PUSH_ID frame. In particular, a server is not able to push until after the
%client sends a MAX_PUSH_ID frame. A client sends MAX_PUSH_ID frames to control
%the number of pushes that a server can promise. A server SHOULD use push IDs
%sequentially, beginning from zero. A client MUST treat receipt of a push
%stream as a connection error of type H3_ID_ERROR when no MAX_PUSH_ID frame has
%been sent or when the stream references a push ID that is greater than the
%maximum push ID.
%% When the same push ID is promised on multiple request streams, the
%decompressed request field sections MUST contain the same fields in the same
%order, and both the name and the value in each field MUST be identical.
%% Not all requests can be pushed. A server MAY push requests that have the following properties:
%cacheable; see Section 9.2.3 of [HTTP]
%safe; see Section 9.2.1 of [HTTP]
%does not include request content or a trailer section
%
%% The server MUST include a value in the :authority pseudo-header field for
%which the server is authoritative. If the client has not yet validated the
%connection for the origin indicated by the pushed request, it MUST perform the
%same verification process it would do before sending a request for that origin
%on the connection; see Section 3.3. If this verification fails, the client
%MUST NOT consider the server authoritative for that origin.
%% Clients SHOULD send a CANCEL_PUSH frame upon receipt of a PUSH_PROMISE frame
%carrying a request that is not cacheable, is not known to be safe, that
%indicates the presence of request content, or for which it does not consider
%the server authoritative. Any corresponding responses MUST NOT be used or
%cached.
%% Ordering of a PUSH_PROMISE frame in relation to certain parts of the
%response is important. The server SHOULD send PUSH_PROMISE frames prior to
%sending HEADERS or DATA frames that reference the promised responses. This
%reduces the chance that a client requests a resource that will be pushed by
%the server.
%% Push stream data can also arrive after a client has cancelled a push. In
%this case, the client can abort reading the stream with an error code of
%H3_REQUEST_CANCELLED. This asks the server not to transfer additional data and
%indicates that it will be discarded upon receipt.

%% 5. Connection Closure
%% 5.1. Idle Connections
%% HTTP/3 implementations will need to open a new HTTP/3 connection for new
%requests if the existing connection has been idle for longer than the idle
%timeout negotiated during the QUIC handshake, and they SHOULD do so if
%approaching the idle timeout; see Section 10.1 of [QUIC-TRANSPORT].
%% Servers SHOULD NOT actively keep connections open.

%% 5.2. Connection Shutdown
%% Endpoints initiate the graceful shutdown of an HTTP/3 connection by sending
%a GOAWAY frame. The GOAWAY frame contains an identifier that indicates to the
%receiver the range of requests or pushes that were or might be processed in
%this connection. The server sends a client-initiated bidirectional stream ID;
%the client sends a push ID. Requests or pushes with the indicated identifier
%or greater are rejected (Section 4.1.1) by the sender of the GOAWAY. This
%identifier MAY be zero if no requests or pushes were processed.
%% Upon sending a GOAWAY frame, the endpoint SHOULD explicitly cancel (see
%Sections 4.1.1 and 7.2.3) any requests or pushes that have identifiers greater
%than or equal to the one indicated, in order to clean up transport state for
%the affected streams. The endpoint SHOULD continue to do so as more requests
%or pushes arrive.
%% Endpoints MUST NOT initiate new requests or promise new pushes on the
%connection after receipt of a GOAWAY frame from the peer.
%% Requests on stream IDs less than the stream ID in a GOAWAY frame from the
%server might have been processed; their status cannot be known until a
%response is received, the stream is reset individually, another GOAWAY is
%received with a lower stream ID than that of the request in question, or the
%connection terminates.
%% Servers MAY reject individual requests on streams below the indicated ID if
%these requests were not processed.
%% If a server receives a GOAWAY frame after having promised pushes with a push
%ID greater than or equal to the identifier contained in the GOAWAY frame,
%those pushes will not be accepted.
%% Servers SHOULD send a GOAWAY frame when the closing of a connection is known
%in advance, even if the advance notice is small, so that the remote peer can
%know whether or not a request has been partially processed.
%% An endpoint MAY send multiple GOAWAY frames indicating different
%identifiers, but the identifier in each frame MUST NOT be greater than the
%identifier in any previous frame, since clients might already have retried
%unprocessed requests on another HTTP connection. Receiving a GOAWAY containing
%a larger identifier than previously received MUST be treated as a connection
%error of type H3_ID_ERROR.
%% An endpoint that is attempting to gracefully shut down a connection can send
%a GOAWAY frame with a value set to the maximum possible value (262-4 for
%servers, 262-1 for clients).
%% Even when a GOAWAY indicates that a given request or push will not be
%processed or accepted upon receipt, the underlying transport resources still
%exist. The endpoint that initiated these requests can cancel them to clean up
%transport state.
%% Once all accepted requests and pushes have been processed, the endpoint can
%permit the connection to become idle, or it MAY initiate an immediate closure
%of the connection. An endpoint that completes a graceful shutdown SHOULD use
%the H3_NO_ERROR error code when closing the connection.
%% If a client has consumed all available bidirectional stream IDs with
%requests, the server need not send a GOAWAY frame, since the client is unable
%to make further requests. @todo OK that one's some weird stuff lol

%% 5.3. Immediate Application Closure
%% Before closing the connection, a GOAWAY frame MAY be sent to allow the
%client to retry some requests. Including the GOAWAY frame in the same packet
%as the QUIC CONNECTION_CLOSE frame improves the chances of the frame being
%received by clients.

%% 6. Stream Mapping and Usage
%% 6.1. Bidirectional Streams
%% an HTTP/3 server SHOULD configure non-zero minimum values for the number of
%permitted streams and the initial stream flow-control window. So as to not
%unnecessarily limit parallelism, at least 100 request streams SHOULD be
%permitted at a time.

%% 6.2. Unidirectional Streams
%% Therefore, the transport parameters sent by both clients and servers MUST
%allow the peer to create at least three unidirectional streams. These
%transport parameters SHOULD also provide at least 1,024 bytes of flow-control
%credit to each unidirectional stream.
%% Note that an endpoint is not required to grant additional credits to create
%more unidirectional streams if its peer consumes all the initial credits
%before creating the critical unidirectional streams. Endpoints SHOULD create
%the HTTP control stream as well as the unidirectional streams required by
%mandatory extensions (such as the QPACK encoder and decoder streams) first,
%and then create additional streams as allowed by their peer.
%% Recipients of unknown stream types MUST either abort reading of the stream
%or discard incoming data without further processing. If reading is aborted,
%the recipient SHOULD use the H3_STREAM_CREATION_ERROR error code or a reserved
%error code (Section 8.1). The recipient MUST NOT consider unknown stream types
%to be a connection error of any kind.
%% As certain stream types can affect connection state, a recipient SHOULD NOT
%discard data from incoming unidirectional streams prior to reading the stream
%type.
%% Implementations MAY send stream types before knowing whether the peer
%supports them. However, stream types that could modify the state or semantics
%of existing protocol components, including QPACK or other extensions, MUST NOT
%be sent until the peer is known to support them.
%% A receiver MUST tolerate unidirectional streams being closed or reset prior
%to the reception of the unidirectional stream header.

%% 6.2.1. Control Streams
%% A control stream is indicated by a stream type of 0x00. Data on this stream
%consists of HTTP/3 frames, as defined in Section 7.2.
%% Each side MUST initiate a single control stream at the beginning of the
%connection and send its SETTINGS frame as the first frame on this stream. If
%the first frame of the control stream is any other frame type, this MUST be
%treated as a connection error of type H3_MISSING_SETTINGS. Only one control
%stream per peer is permitted; receipt of a second stream claiming to be a
%control stream MUST be treated as a connection error of type
%H3_STREAM_CREATION_ERROR. The sender MUST NOT close the control stream, and
%the receiver MUST NOT request that the sender close the control stream. If
%either control stream is closed at any point, this MUST be treated as a
%connection error of type H3_CLOSED_CRITICAL_STREAM. Connection errors are
%described in Section 8.
%% Because the contents of the control stream are used to manage the behavior
%of other streams, endpoints SHOULD provide enough flow-control credit to keep
%the peer's control stream from becoming blocked.

%% 6.2.2. Push Streams
%% A push stream is indicated by a stream type of 0x01, followed by the push ID
%of the promise that it fulfills, encoded as a variable-length integer. The
%remaining data on this stream consists of HTTP/3 frames, as defined in Section
%7.2, and fulfills a promised server push by zero or more interim HTTP
%responses followed by a single final HTTP response, as defined in Section 4.1.
%Server push and push IDs are described in Section 4.6.
%% Only servers can push; if a server receives a client-initiated push stream,
%this MUST be treated as a connection error of type H3_STREAM_CREATION_ERROR.
%% Each push ID MUST only be used once in a push stream header. If a client
%detects that a push stream header includes a push ID that was used in another
%push stream header, the client MUST treat this as a connection error of type
%H3_ID_ERROR.

%% 6.2.3. Reserved Stream Types
%% Stream types of the format 0x1f * N + 0x21 for non-negative integer values
%of N are reserved to exercise the requirement that unknown types be ignored.
%These streams have no semantics, and they can be sent when application-layer
%padding is desired. They MAY also be sent on connections where no data is
%currently being transferred. Endpoints MUST NOT consider these streams to have
%any meaning upon receipt.
%% The payload and length of the stream are selected in any manner the sending
%implementation chooses. When sending a reserved stream type, the
%implementation MAY either terminate the stream cleanly or reset it. When
%resetting the stream, either the H3_NO_ERROR error code or a reserved error
%code (Section 8.1) SHOULD be used.

%% 7. HTTP Framing Layer
%% Note that, unlike QUIC frames, HTTP/3 frames can span multiple packets.

%% 7.1. Frame Layout
%% Each frame's payload MUST contain exactly the fields identified in its
%description. A frame payload that contains additional bytes after the
%identified fields or a frame payload that terminates before the end of the
%identified fields MUST be treated as a connection error of type
%H3_FRAME_ERROR. In particular, redundant length encodings MUST be verified to
%be self-consistent; see Section 10.8.
%% When a stream terminates cleanly, if the last frame on the stream was
%truncated, this MUST be treated as a connection error of type H3_FRAME_ERROR.
%Streams that terminate abruptly may be reset at any point in a frame.

%% 7.2. Frame Definitions
%% 7.2.1. DATA
%% DATA frames MUST be associated with an HTTP request or response. If a DATA
%frame is received on a control stream, the recipient MUST respond with a
%connection error of type H3_FRAME_UNEXPECTED.

%% 7.2.2. HEADERS
%% HEADERS frames can only be sent on request streams or push streams. If a
%HEADERS frame is received on a control stream, the recipient MUST respond with
%a connection error of type H3_FRAME_UNEXPECTED.

%% 7.2.3. CANCEL_PUSH
%% When a client sends a CANCEL_PUSH frame, it is indicating that it does not
%wish to receive the promised resource. The server SHOULD abort sending the
%resource, but the mechanism to do so depends on the state of the corresponding
%push stream. If the server has not yet created a push stream, it does not
%create one. If the push stream is open, the server SHOULD abruptly terminate
%that stream. If the push stream has already ended, the server MAY still
%abruptly terminate the stream or MAY take no action.
%% A server sends a CANCEL_PUSH frame to indicate that it will not be
%fulfilling a promise that was previously sent. The client cannot expect the
%corresponding promise to be fulfilled, unless it has already received and
%processed the promised response. Regardless of whether a push stream has been
%opened, a server SHOULD send a CANCEL_PUSH frame when it determines that
%promise will not be fulfilled. If a stream has already been opened, the server
%can abort sending on the stream with an error code of H3_REQUEST_CANCELLED.
%% Sending a CANCEL_PUSH frame has no direct effect on the state of existing
%push streams. A client SHOULD NOT send a CANCEL_PUSH frame when it has already
%received a corresponding push stream. A push stream could arrive after a
%client has sent a CANCEL_PUSH frame, because a server might not have processed
%the CANCEL_PUSH. The client SHOULD abort reading the stream with an error code
%of H3_REQUEST_CANCELLED.
%% A CANCEL_PUSH frame is sent on the control stream. Receiving a CANCEL_PUSH
%frame on a stream other than the control stream MUST be treated as a
%connection error of type H3_FRAME_UNEXPECTED.
%% If a CANCEL_PUSH frame is received that references a push ID greater than
%currently allowed on the connection, this MUST be treated as a connection
%error of type H3_ID_ERROR.
%% If the client receives a CANCEL_PUSH frame, that frame might identify a push
%ID that has not yet been mentioned by a PUSH_PROMISE frame due to reordering.
%If a server receives a CANCEL_PUSH frame for a push ID that has not yet been
%mentioned by a PUSH_PROMISE frame, this MUST be treated as a connection error
%of type H3_ID_ERROR.

%% 7.2.4. SETTINGS
%% A SETTINGS frame MUST be sent as the first frame of each control stream (see
%Section 6.2.1) by each peer, and it MUST NOT be sent subsequently. If an
%endpoint receives a second SETTINGS frame on the control stream, the endpoint
%MUST respond with a connection error of type H3_FRAME_UNEXPECTED.
%% SETTINGS frames MUST NOT be sent on any stream other than the control
%stream. If an endpoint receives a SETTINGS frame on a different stream, the
%endpoint MUST respond with a connection error of type H3_FRAME_UNEXPECTED.
%% The same setting identifier MUST NOT occur more than once in the SETTINGS
%frame. A receiver MAY treat the presence of duplicate setting identifiers as a
%connection error of type H3_SETTINGS_ERROR.
%% An implementation MUST ignore any parameter with an identifier it does not understand.

%% 7.2.4.1. Defined SETTINGS Parameters
%% Setting identifiers of the format 0x1f * N + 0x21 for non-negative integer
%values of N are reserved to exercise the requirement that unknown identifiers
%be ignored. Such settings have no defined meaning. Endpoints SHOULD include at
%least one such setting in their SETTINGS frame. Endpoints MUST NOT consider
%such settings to have any meaning upon receipt.
%% -> try sending COW\0 BOY\0 if that fits the encoding and restrictions
%otherwise something similar
%% Setting identifiers that were defined in [HTTP/2] where there is no
%corresponding HTTP/3 setting have also been reserved (Section 11.2.2). These
%reserved settings MUST NOT be sent, and their receipt MUST be treated as a
%connection error of type H3_SETTINGS_ERROR.

%% 7.2.4.2. Initialization
%% An HTTP implementation MUST NOT send frames or requests that would be
%invalid based on its current understanding of the peer's settings.
%% All settings begin at an initial value. Each endpoint SHOULD use these
%initial values to send messages before the peer's SETTINGS frame has arrived,
%as packets carrying the settings can be lost or delayed. When the SETTINGS
%frame arrives, any settings are changed to their new values.
%% Endpoints MUST NOT require any data to be received from the peer prior to
%sending the SETTINGS frame; settings MUST be sent as soon as the transport is
%ready to send data.
%% A server MAY accept 0-RTT and subsequently provide different settings in its
%SETTINGS frame. If 0-RTT data is accepted by the server, its SETTINGS frame
%MUST NOT reduce any limits or alter any values that might be violated by the
%client with its 0-RTT data. The server MUST include all settings that differ
%from their default values. If a server accepts 0-RTT but then sends settings
%that are not compatible with the previously specified settings, this MUST be
%treated as a connection error of type H3_SETTINGS_ERROR. If a server accepts
%0-RTT but then sends a SETTINGS frame that omits a setting value that the
%client understands (apart from reserved setting identifiers) that was
%previously specified to have a non-default value, this MUST be treated as a
%connection error of type H3_SETTINGS_ERROR.

%% 7.2.5. PUSH_PROMISE
%% A server MUST NOT use a push ID that is larger than the client has provided
%in a MAX_PUSH_ID frame (Section 7.2.7).
%% A server MAY use the same push ID in multiple PUSH_PROMISE frames. If so,
%the decompressed request header sets MUST contain the same fields in the same
%order, and both the name and the value in each field MUST be exact matches.
%% Allowing duplicate references to the same push ID is primarily to reduce
%duplication caused by concurrent requests. A server SHOULD avoid reusing a
%push ID over a long period. Clients are likely to consume server push
%responses and not retain them for reuse over time. Clients that see a
%PUSH_PROMISE frame that uses a push ID that they have already consumed and
%discarded are forced to ignore the promise.
%% A client MUST NOT send a PUSH_PROMISE frame. A server MUST treat the receipt
%of a PUSH_PROMISE frame as a connection error of type H3_FRAME_UNEXPECTED.

%% 7.2.6. GOAWAY
%% (not sure what applies to the server, should the server reject GOAWAY on
%non-control stream too?)

%% 7.2.7. MAX_PUSH_ID
%% Receipt of a MAX_PUSH_ID frame on any other stream MUST be treated as a
%connection error of type H3_FRAME_UNEXPECTED.
%% The maximum push ID is unset when an HTTP/3 connection is created, meaning
%that a server cannot push until it receives a MAX_PUSH_ID frame.
%% A MAX_PUSH_ID frame cannot reduce the maximum push ID; receipt of a
%MAX_PUSH_ID frame that contains a smaller value than previously received MUST
%be treated as a connection error of type H3_ID_ERROR.

%% 7.2.8. Reserved Frame Types
%% These frames have no semantics, and they MAY be sent on any stream where
%frames are allowed to be sent. This enables their use for application-layer
%padding. Endpoints MUST NOT consider these frames to have any meaning upon
%receipt.
%% Frame types that were used in HTTP/2 where there is no corresponding HTTP/3
%frame have also been reserved (Section 11.2.1). These frame types MUST NOT be
%sent, and their receipt MUST be treated as a connection error of type
%H3_FRAME_UNEXPECTED.

%% 8. Error Handling
%% An endpoint MAY choose to treat a stream error as a connection error under
%certain circumstances, closing the entire connection in response to a
%condition on a single stream.
%% Because new error codes can be defined without negotiation (see Section 9),
%use of an error code in an unexpected context or receipt of an unknown error
%code MUST be treated as equivalent to H3_NO_ERROR.

%% 8.1. HTTP/3 Error Codes
%% H3_INTERNAL_ERROR (0x0102): An internal error has occurred in the HTTP stack.
%% H3_FRAME_ERROR (0x0106): A frame that fails to satisfy layout requirements
%or with an invalid size was received.
%% H3_EXCESSIVE_LOAD (0x0107): The endpoint detected that its peer is
%exhibiting a behavior that might be generating excessive load.
%% (more)
%% Error codes of the format 0x1f * N + 0x21 for non-negative integer values of
%N are reserved to exercise the requirement that unknown error codes be treated
%as equivalent to H3_NO_ERROR (Section 9). Implementations SHOULD select an
%error code from this space with some probability when they would have sent
%H3_NO_ERROR.

%% 9. Extensions to HTTP/3
%% Extensions are permitted to use new frame types (Section 7.2), new settings
%(Section 7.2.4.1), new error codes (Section 8), or new unidirectional stream
%types (Section 6.2). Registries are established for managing these extension
%points: frame types (Section 11.2.1), settings (Section 11.2.2), error codes
%(Section 11.2.3), and stream types (Section 11.2.4).
%% Implementations MUST ignore unknown or unsupported values in all extensible
%protocol elements. Implementations MUST discard data or abort reading on
%unidirectional streams that have unknown or unsupported types. This means that
%any of these extension points can be safely used by extensions without prior
%arrangement or negotiation. However, where a known frame type is required to
%be in a specific location, such as the SETTINGS frame as the first frame of
%the control stream (see Section 6.2.1), an unknown frame type does not satisfy
%that requirement and SHOULD be treated as an error.
%% If a setting is used for extension negotiation, the default value MUST be
%defined in such a fashion that the extension is disabled if the setting is
%omitted.

%% 10. Security Considerations
%% 10.3. Intermediary-Encapsulation Attacks
%% Requests or responses containing invalid field names MUST be treated as malformed.
%% Any request or response that contains a character not permitted in a field
%value MUST be treated as malformed.

%% 10.5. Denial-of-Service Considerations
%% Implementations SHOULD track the use of these features and set limits on
%their use. An endpoint MAY treat activity that is suspicious as a connection
%error of type H3_EXCESSIVE_LOAD, but false positives will result in disrupting
%valid connections and requests.

%% 10.5.1. Limits on Field Section Size
%% An endpoint can use the SETTINGS_MAX_FIELD_SECTION_SIZE (Section 4.2.2)
%setting to advise peers of limits that might apply on the size of field
%sections.
%% A server that receives a larger field section than it is willing to handle
%can send an HTTP 431 (Request Header Fields Too Large) status code
%([RFC6585]).

%% 10.6. Use of Compression
%% Implementations communicating on a secure channel MUST NOT compress content
%that includes both confidential and attacker-controlled data unless separate
%compression contexts are used for each source of data. Compression MUST NOT be
%used if the source of data cannot be reliably determined.

%% 10.8. Frame Parsing
%% An implementation MUST ensure that the length of a frame exactly matches the
%length of the fields it contains.

%% 10.9. Early Data
%% The anti-replay mitigations in [HTTP-REPLAY] MUST be applied when using HTTP/3 with 0-RTT.

%% 10.10. Migration
%% Certain HTTP implementations use the client address for logging or
%access-control purposes. Since a QUIC client's address might change during a
%connection (and future versions might support simultaneous use of multiple
%addresses), such implementations will need to either actively retrieve the
%client's current address or addresses when they are relevant or explicitly
%accept that the original address might change. -> documentation for now

%% 11.2.1. Frame Types
%% Reserved types: 0x02 0x06 0x08 0x09

%% 11.2.2. Settings Parameters
%% Reserved settings: 0x00 0x02 0x03 0x04 0x05

%% Appendix A. Considerations for Transitioning from HTTP/2
%% A.1. Streams
%% QUIC considers a stream closed when all data has been received and sent data
%has been acknowledged by the peer. HTTP/2 considers a stream closed when the
%frame containing the END_STREAM bit has been committed to the transport. As a
%result, the stream for an equivalent exchange could remain "active" for a
%longer period of time. HTTP/3 servers might choose to permit a larger number
%of concurrent client-initiated bidirectional streams to achieve equivalent
%concurrency to HTTP/2, depending on the expected usage patterns. ->
%documentation?

%% A.3. HTTP/2 SETTINGS Parameters
%% SETTINGS_MAX_FRAME_SIZE (0x05): This setting has no equivalent in HTTP/3.
%Specifying a setting with the identifier 0x05 (corresponding to the
%SETTINGS_MAX_FRAME_SIZE parameter) in the HTTP/3 SETTINGS frame is an error.
%-> do we still want a limit, if so how?
