%% This module sends a hello world response.

-module(quic_hello_h).

-export([init/2]).

-spec init(_, _) -> _.
init(Req, Opts) ->
	{ok, cowboy_req:reply(200, #{}, <<"Hello world!">>, Req), Opts}.
