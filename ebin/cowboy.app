{application, 'cowboy', [
	{description, "Small, fast, modern HTTP server."},
	{vsn, "2.10.0"},
	{modules, ['cow_http3','cow_http3_machine','cowboy','cowboy_app','cowboy_bstr','cowboy_children','cowboy_clear','cowboy_clock','cowboy_compress_h','cowboy_constraints','cowboy_handler','cowboy_http','cowboy_http2','cowboy_http3','cowboy_loop','cowboy_metrics_h','cowboy_middleware','cowboy_quicer','cowboy_req','cowboy_rest','cowboy_router','cowboy_static','cowboy_stream','cowboy_stream_h','cowboy_sub_protocol','cowboy_sup','cowboy_tls','cowboy_tracer_h','cowboy_websocket','quic_hello_h']},
	{registered, [cowboy_sup,cowboy_clock]},
	{applications, [kernel,stdlib,crypto,cowlib,ranch,quicer]},
	{mod, {cowboy_app, []}},
	{env, []}
]}.