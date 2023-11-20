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

%% QUIC transport using the emqx/quicer NIF.

-module(cowboy_quicer).

%% Connection.
-export([peername/1]).
-export([sockname/1]).
-export([shutdown/2]).

%% Streams.
-export([start_unidi_stream/2]).
-export([send/3]).
-export([send/4]).
-export([shutdown_stream/4]).

%% Messages.
-export([handle/1]).

-define(COWBOY_QUICER, 1). %% @todo Remove when merging to master.

-ifndef(COWBOY_QUICER).

%% @todo Error out on all callbacks.

-else.

-include_lib("quicer/include/quicer.hrl").

%% Connection.

-spec peername(_) -> _. %% @todo

peername(Conn) ->
	quicer:peername(Conn).

-spec sockname(_) -> _. %% @todo

sockname(Conn) ->
	quicer:sockname(Conn).

-spec shutdown(_, _) -> _. %% @todo

shutdown(Conn, ErrorCode) ->
	quicer:shutdown_connection(Conn,
		?QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
		ErrorCode).

%% Streams.

-spec start_unidi_stream(_, _) -> _. %% @todo

start_unidi_stream(Conn, HeaderData) ->
	{ok, StreamRef} = quicer:start_stream(Conn,
		#{open_flag => ?QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL}),
	{ok, _} = quicer:send(StreamRef, HeaderData),
	{ok, StreamID} = quicer:get_stream_id(StreamRef),
	put({quicer_stream, StreamID}, StreamRef),
	{ok, StreamID}.

-spec send(_, _, _) -> _. %% @todo

send(Conn, StreamID, Data) ->
	send(Conn, StreamID, Data, nofin).

-spec send(_, _, _, _) -> _. %% @todo

send(_Conn, StreamID, Data, IsFin) ->
	StreamRef = get({quicer_stream, StreamID}),
	Size = iolist_size(Data),
	case quicer:send(StreamRef, Data, send_flag(IsFin)) of
		{ok, _} -> ok;
		Error -> Error
	end.

send_flag(nofin) -> ?QUIC_SEND_FLAG_NONE;
send_flag(fin) -> ?QUIC_SEND_FLAG_FIN.

-spec shutdown_stream(_, _, _, _) -> _. %% @todo

shutdown_stream(_Conn, StreamID, Dir, ErrorCode) ->
	StreamRef = get({quicer_stream, StreamID}),
	Res = quicer:shutdown_stream(StreamRef, shutdown_flag(Dir), ErrorCode, infinity),
%	ct:pal("~p shutdown_stream res ~p", [self(), Res]),
	ok.

shutdown_flag(both) -> ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT;
shutdown_flag(receiving) -> ?QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE.

%% Messages.

%% @todo Probably should have the Conn given too?
-spec handle(_) -> _. %% @todo

handle({quic, Data, StreamRef, #{flags := Flags}}) when is_binary(Data) ->
	{ok, StreamID} = quicer:get_stream_id(StreamRef),
	IsFin = case Flags band ?QUIC_RECEIVE_FLAG_FIN of
		?QUIC_RECEIVE_FLAG_FIN -> fin;
		_ -> nofin
	end,
	{data, StreamID, IsFin, Data};
%% QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED.
handle({quic, new_stream, StreamRef, #{flags := Flags}}) ->
	ok = quicer:setopt(StreamRef, active, true),
	{ok, StreamID} = quicer:get_stream_id(StreamRef),
	put({quicer_stream, StreamID}, StreamRef),
	StreamType = case quicer:is_unidirectional(Flags) of
		true -> unidi;
		false -> bidi
	end,
	{stream_started, StreamID, StreamType};
%% QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE.
handle({quic, stream_closed, StreamRef, #{error := ErrorCode}}) ->
	{ok, StreamID} = quicer:get_stream_id(StreamRef),
	{stream_closed, StreamID, ErrorCode};
%% QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE.
handle({quic, closed, Conn, _Flags}) ->
	quicer:close_connection(Conn),
	closed;
%% The following events are currently ignored either because
%% I do not know what they do or because we do not need to
%% take action.
handle({quic, streams_available, _Conn, Props}) ->
	ok;
handle({quic, dgram_state_changed, _Conn, _Props}) ->
	ok;
%% QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT
handle({quic, transport_shutdown, _Conn, _Flags}) ->
	ok;
handle({quic, peer_send_shutdown, _StreamRef, undefined}) ->
%	ct:pal("peer_send_shutdown ~p", [StreamRef]),
	ok;
handle({quic, send_shutdown_complete, _StreamRef, _IsGraceful}) ->
	ok;
handle({quic, shutdown, _Conn, success}) ->
	ok;
handle(Msg) ->
	ct:pal("Ignoring quicer message ~p", [Msg]),
	ok.

-endif.
