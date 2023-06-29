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

-module(cow_http3).

%% Parsing.
-export([parse/1]).
-export([parse_unidi_stream_header/1]).

%% Building.
-export([data/1]).
-export([headers/1]).

%% Parsing.

-spec parse(_) -> _. %% @todo

%%
%% DATA frames.
%%
parse(<<0, 0:2, Len:6, Data:Len/binary, Rest/bits>>) ->
	{ok, {data, Data}, Rest};
parse(<<0, 1:2, Len:14, Data:Len/binary, Rest/bits>>) ->
	{ok, {data, Data}, Rest};
parse(<<0, 2:2, Len:30, Data:Len/binary, Rest/bits>>) ->
	{ok, {data, Data}, Rest};
parse(<<0, 3:2, Len:62, Data:Len/binary, Rest/bits>>) ->
	{ok, {data, Data}, Rest};
%% DATA frames may be split over multiple QUIC packets
%% but we want to process them immediately rather than
%% risk buffering a very large payload.
parse(<<0, 0:2, Len:6, Data/bits>>) when byte_size(Data) < Len ->
	{more, {data, Data}, Len - byte_size(Data)};
parse(<<0, 1:2, Len:14, Data/bits>>) when byte_size(Data) < Len ->
	{more, {data, Data}, Len - byte_size(Data)};
parse(<<0, 2:2, Len:30, Data/bits>>) when byte_size(Data) < Len ->
	{more, {data, Data}, Len - byte_size(Data)};
parse(<<0, 3:2, Len:62, Data/bits>>) when byte_size(Data) < Len ->
	{more, {data, Data}, Len - byte_size(Data)};
%%
%% HEADERS frames.
%%
parse(<<1, 0:2, Len:6, EncodedFieldSection:Len/binary, Rest/bits>>) ->
	{ok, {headers, EncodedFieldSection}, Rest};
parse(<<1, 1:2, Len:14, EncodedFieldSection:Len/binary, Rest/bits>>) ->
	{ok, {headers, EncodedFieldSection}, Rest};
parse(<<1, 2:2, Len:30, EncodedFieldSection:Len/binary, Rest/bits>>) ->
	{ok, {headers, EncodedFieldSection}, Rest};
parse(<<1, 3:2, Len:62, EncodedFieldSection:Len/binary, Rest/bits>>) ->
	{ok, {headers, EncodedFieldSection}, Rest};
%%
%% CANCEL_PUSH frames.
%%
parse(<<3, 0:2, 1:6, 0:2, PushID:6, Rest/bits>>) ->
	{ok, {cancel_push, PushID}, Rest};
parse(<<3, 0:2, 2:6, 1:2, PushID:14, Rest/bits>>) ->
	{ok, {cancel_push, PushID}, Rest};
parse(<<3, 0:2, 4:6, 2:2, PushID:30, Rest/bits>>) ->
	{ok, {cancel_push, PushID}, Rest};
parse(<<3, 0:2, 8:6, 3:2, PushID:62, Rest/bits>>) ->
	{ok, {cancel_push, PushID}, Rest};
parse(<<3, _/bits>>) ->
	{connection_error, h3_frame_error,
		'CANCEL_PUSH frames payload MUST be 1, 2, 4 or 8 bytes wide. (RFC9114 7.1, RFC9114 7.2.3)'};
%%
%% SETTINGS frames.
%%
parse(<<4, 0:2, Len:6, Rest/bits>>) when byte_size(Rest) >= Len ->
	parse_settings_id(Rest, Len, #{});
parse(<<4, 1:2, Len:14, Rest/bits>>) when byte_size(Rest) >= Len ->
	parse_settings_id(Rest, Len, #{});
parse(<<4, 2:2, Len:30, Rest/bits>>) when byte_size(Rest) >= Len ->
	parse_settings_id(Rest, Len, #{});
parse(<<4, 3:2, Len:62, Rest/bits>>) when byte_size(Rest) >= Len ->
	parse_settings_id(Rest, Len, #{});
%%
%% PUSH_PROMISE frames.
%%
parse(<<5, 0:2, Len:6, Rest/bits>>) when byte_size(Rest) >= Len ->
	parse_push_promise(Rest, Len);
parse(<<5, 1:2, Len:14, Rest/bits>>) when byte_size(Rest) >= Len ->
	parse_push_promise(Rest, Len);
parse(<<5, 2:2, Len:30, Rest/bits>>) when byte_size(Rest) >= Len ->
	parse_push_promise(Rest, Len);
parse(<<5, 3:2, Len:62, Rest/bits>>) when byte_size(Rest) >= Len ->
	parse_push_promise(Rest, Len);
%%
%% GOAWAY frames.
%%
parse(<<7, 0:2, 1:6, 0:2, StreamOrPushID:6, Rest/bits>>) ->
	{ok, {goaway, StreamOrPushID}, Rest};
parse(<<7, 0:2, 2:6, 1:2, StreamOrPushID:14, Rest/bits>>) ->
	{ok, {goaway, StreamOrPushID}, Rest};
parse(<<7, 0:2, 4:6, 2:2, StreamOrPushID:30, Rest/bits>>) ->
	{ok, {goaway, StreamOrPushID}, Rest};
parse(<<7, 0:2, 8:6, 3:2, StreamOrPushID:62, Rest/bits>>) ->
	{ok, {goaway, StreamOrPushID}, Rest};
parse(<<7, _/bits>>) ->
	{connection_error, h3_frame_error,
		'GOAWAY frames payload MUST be 1, 2, 4 or 8 bytes wide. (RFC9114 7.1, RFC9114 7.2.6)'};
%%
%% MAX_PUSH_ID frames.
%%
parse(<<13, 0:2, 1:6, 0:2, PushID:6, Rest/bits>>) ->
	{ok, {max_push_id, PushID}, Rest};
parse(<<13, 0:2, 2:6, 1:2, PushID:14, Rest/bits>>) ->
	{ok, {max_push_id, PushID}, Rest};
parse(<<13, 0:2, 4:6, 2:2, PushID:30, Rest/bits>>) ->
	{ok, {max_push_id, PushID}, Rest};
parse(<<13, 0:2, 8:6, 3:2, PushID:62, Rest/bits>>) ->
	{ok, {max_push_id, PushID}, Rest};
parse(<<13, _/bits>>) ->
	{connection_error, h3_frame_error,
		'MAX_PUSH_ID frames payload MUST be 1, 2, 4 or 8 bytes wide. (RFC9114 7.1, RFC9114 7.2.6)'};
%%
%% HTTP/2 frame types must be rejected.
%%
parse(<<2, _/bits>>) ->
	{connection_error, h3_frame_unexpected,
		'HTTP/2 PRIORITY frame not defined for HTTP/3 must be rejected. (RFC9114 7.2.8)'};
parse(<<6, _/bits>>) ->
	{connection_error, h3_frame_unexpected,
		'HTTP/2 PING frame not defined for HTTP/3 must be rejected. (RFC9114 7.2.8)'};
parse(<<8, _/bits>>) ->
	{connection_error, h3_frame_unexpected,
		'HTTP/2 WINDOW_UPDATE frame not defined for HTTP/3 must be rejected. (RFC9114 7.2.8)'};
parse(<<9, _/bits>>) ->
	{connection_error, h3_frame_unexpected,
		'HTTP/2 CONTINUATION frame not defined for HTTP/3 must be rejected. (RFC9114 7.2.8)'};
%%
%% Unknown frames must be ignored.
%%
%% @todo This can lead to DoS especially for larger frames
%%       and HTTP/3 doesn't have a limit in SETTINGS. Perhaps
%%       we should have an option to limit the stream buffer
%%       size and error out (h3_excessive_load) when exceeded.
parse(<<0:2, Type:6, 0:2, Len:6, _:Len/binary, Rest/bits>>)
		when Type =:= 10; Type =:= 11; Type =:= 12; Type > 13 ->
	{ignore, Rest};
parse(<<0:2, Type:6, 1:2, Len:14, _:Len/binary, Rest/bits>>)
		when Type =:= 10; Type =:= 11; Type =:= 12; Type > 13 ->
	{ignore, Rest};
parse(<<0:2, Type:6, 2:2, Len:30, _:Len/binary, Rest/bits>>)
		when Type =:= 10; Type =:= 11; Type =:= 12; Type > 13 ->
	{ignore, Rest};
parse(<<0:2, Type:6, 3:2, Len:62, _:Len/binary, Rest/bits>>)
		when Type =:= 10; Type =:= 11; Type =:= 12; Type > 13 ->
	{ignore, Rest};
parse(<<1:2, _:14, 0:2, Len:6, _:Len/binary, Rest/bits>>) ->
	{ignore, Rest};
parse(<<1:2, _:14, 1:2, Len:14, _:Len/binary, Rest/bits>>) ->
	{ignore, Rest};
parse(<<1:2, _:14, 2:2, Len:30, _:Len/binary, Rest/bits>>) ->
	{ignore, Rest};
parse(<<1:2, _:14, 3:2, Len:62, _:Len/binary, Rest/bits>>) ->
	{ignore, Rest};
parse(<<2:2, _:30, 0:2, Len:6, _:Len/binary, Rest/bits>>) ->
	{ignore, Rest};
parse(<<2:2, _:30, 1:2, Len:14, _:Len/binary, Rest/bits>>) ->
	{ignore, Rest};
parse(<<2:2, _:30, 2:2, Len:30, _:Len/binary, Rest/bits>>) ->
	{ignore, Rest};
parse(<<2:2, _:30, 3:2, Len:62, _:Len/binary, Rest/bits>>) ->
	{ignore, Rest};
parse(<<3:2, _:62, 0:2, Len:6, _:Len/binary, Rest/bits>>) ->
	{ignore, Rest};
parse(<<3:2, _:62, 1:2, Len:14, _:Len/binary, Rest/bits>>) ->
	{ignore, Rest};
parse(<<3:2, _:62, 2:2, Len:30, _:Len/binary, Rest/bits>>) ->
	{ignore, Rest};
parse(<<3:2, _:62, 3:2, Len:62, _:Len/binary, Rest/bits>>) ->
	{ignore, Rest};
%%
%% Incomplete frames for those we fully process only.
%%
parse(_) ->
	more.

parse_settings_id(Rest, 0, Settings) ->
	{ok, {settings, Settings}, Rest};
parse_settings_id(<<0:2, Identifier:6, Rest/bits>>, Len, Settings) when Len >= 1 ->
	parse_settings_val(Rest, Len - 1, Settings, Identifier);
parse_settings_id(<<1:2, Identifier:14, Rest/bits>>, Len, Settings) when Len >= 2 ->
	parse_settings_val(Rest, Len - 2, Settings, Identifier);
parse_settings_id(<<2:2, Identifier:30, Rest/bits>>, Len, Settings) when Len >= 4 ->
	parse_settings_val(Rest, Len - 4, Settings, Identifier);
parse_settings_id(<<3:2, Identifier:62, Rest/bits>>, Len, Settings) when Len >= 8 ->
	parse_settings_val(Rest, Len - 8, Settings, Identifier);
parse_settings_id(_, _, _) ->
	{connection_error, h3_frame_error,
		'SETTINGS payload size exceeds the length given. (RFC9114 7.1, RFC9114 7.2.4)'}.

parse_settings_val(<<0:2, Value:6, Rest/bits>>, Len, Settings, Identifier) when Len >= 1 ->
	parse_settings_id_val(Rest, Len - 1, Settings, Identifier, Value);
parse_settings_val(<<1:2, Value:14, Rest/bits>>, Len, Settings, Identifier) when Len >= 2 ->
	parse_settings_id_val(Rest, Len - 2, Settings, Identifier, Value);
parse_settings_val(<<2:2, Value:30, Rest/bits>>, Len, Settings, Identifier) when Len >= 4 ->
	parse_settings_id_val(Rest, Len - 4, Settings, Identifier, Value);
parse_settings_val(<<3:2, Value:62, Rest/bits>>, Len, Settings, Identifier) when Len >= 8 ->
	parse_settings_id_val(Rest, Len - 8, Settings, Identifier, Value);
parse_settings_val(_, _, _, _) ->
	{connection_error, h3_frame_error,
		'SETTINGS payload size exceeds the length given. (RFC9114 7.1, RFC9114 7.2.4)'}.

parse_settings_id_val(Rest, Len, Settings, Identifier, Value) ->
	case Identifier of
		6 ->
			parse_settings_key_val(Rest, Len, Settings, max_field_section_size, Value);
		_ when Identifier < 6, Identifier =/= 1 ->
			{connection_error, h3_settings_error,
				'HTTP/2 setting not defined for HTTP/3 must be rejected. (RFC9114 7.2.4.1)'};
		%% Unknown settings must be ignored.
		_ ->
			parse_settings_id(Rest, Len, Settings)
	end.

parse_settings_key_val(Rest, Len, Settings, Key, Value) ->
	case Settings of
		#{Key := _} ->
			{connection_error, h3_settings_error,
				'A duplicate setting identifier was found. (RFC9114 7.2.4)'};
		_ ->
			parse_settings_id(Rest, Len, Settings#{Key => Value})
	end.

parse_push_promise(<<0:2, PushID:6, Data/bits>>, Len) ->
	<<EncodedFieldSection:(Len - 1)/bytes, Rest/bits>> = Data,
	{ok, {push_promise, PushID, EncodedFieldSection}, Rest};
parse_push_promise(<<1:2, PushID:14, Data/bits>>, Len) ->
	<<EncodedFieldSection:(Len - 2)/bytes, Rest/bits>> = Data,
	{ok, {push_promise, PushID, EncodedFieldSection}, Rest};
parse_push_promise(<<2:2, PushID:30, Data/bits>>, Len) ->
	<<EncodedFieldSection:(Len - 4)/bytes, Rest/bits>> = Data,
	{ok, {push_promise, PushID, EncodedFieldSection}, Rest};
parse_push_promise(<<3:2, PushID:62, Data/bits>>, Len) ->
	<<EncodedFieldSection:(Len - 8)/bytes, Rest/bits>> = Data,
	{ok, {push_promise, PushID, EncodedFieldSection}, Rest}.

-spec parse_unidi_stream_header(_) -> _. %% @todo

parse_unidi_stream_header(<<0, Rest/bits>>) ->
	{ok, control, Rest};
parse_unidi_stream_header(<<1, Rest/bits>>) ->
	{ok, push, Rest};
parse_unidi_stream_header(<<2, Rest/bits>>) ->
	{ok, encoder, Rest};
parse_unidi_stream_header(<<3, Rest/bits>>) ->
	{ok, decoder, Rest};
parse_unidi_stream_header(<<0:2, _:6, Rest/bits>>) ->
	{undefined, Rest};
parse_unidi_stream_header(<<1:2, _:14, Rest/bits>>) ->
	{undefined, Rest};
parse_unidi_stream_header(<<2:2, _:30, Rest/bits>>) ->
	{undefined, Rest};
parse_unidi_stream_header(<<3:2, _:62, Rest/bits>>) ->
	{undefined, Rest}.

%% Building.

-spec data(_) -> todo.

data(Data) ->
	Len = encode_int(iolist_size(Data)),
	[<<0:8>>, Len, Data].

-spec headers(_) -> todo.

headers(HeaderBlock) ->
	Len = encode_int(iolist_size(HeaderBlock)),
	[<<1:8>>, Len, HeaderBlock].

encode_int(I) when I < 64 ->
	<<0:2, I:6>>;
encode_int(I) when I < 16384 ->
	<<1:2, I:14>>;
encode_int(I) when I < 1073741824 ->
	<<2:2, I:30>>;
encode_int(I) when I < 4611686018427387904 ->
	<<3:2, I:62>>.
