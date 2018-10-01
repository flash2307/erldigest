-module(erldigest_tests).
-include_lib("eunit/include/eunit.hrl").

rfc_2617_http_example_test() ->
  meck:new(erldigest_nonce_generator, [passthrough, unstick, nolink]),
  meck:expect(erldigest_nonce_generator, generate_nonce, 0, {<<"00000001">>, <<"0a4f113b">>}),
  Challenge = <<"Digest realm=\"testrealm@host.com\", ",
                        "qop=\"auth,auth-int\", ",
                        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", ",
                        "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"">>,
  {ok, Response} = erldigest:calculate_response(<<"GET">>, <<"/dir/index.html">>, Challenge, <<"Mufasa">>, <<"Circle Of Life">>),
  Expected = <<"Digest username=\"Mufasa\",",
                        "realm=\"testrealm@host.com\",",
                        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",",
                        "uri=\"/dir/index.html\",",
                        "response=\"6629fae49393a05397450978507c4ef1\",",
                        "cnonce=\"0a4f113b\",",
                        "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\",",
                        "qop=\"auth,auth-int\",",
                        "nc=00000001">>,
  meck:unload(erldigest_nonce_generator),
  erldigest_test_utils:assert_response_are_equivalent(Expected, Response).

another_http_example_test() ->
  meck:new(erldigest_nonce_generator, [passthrough, unstick, nolink]),
  meck:expect(erldigest_nonce_generator, generate_nonce, 0, {<<"00000001">>, <<"61417766e50cb980">>}),
  Challenge = <<"Digest realm=\"test.dev\", ",
                        "qop=\"auth\", ",
                        "nonce=\"064af982c5b571cea6450d8eda91c20d\", ",
                        "opaque=\"d8ea7aa61a1693024c4cc3a516f49b3c\"">>,
  {ok, Response} = erldigest:calculate_response(<<"GET">>, <<"/login">>, Challenge, <<"user.name">>, <<"s3cr3tP@ssw0rd">>),
  Expected = <<"Digest username=\"user.name\",",
                        "realm=\"test.dev\",",
                        "nonce=\"064af982c5b571cea6450d8eda91c20d\",",
                        "uri=\"/login\",",
                        "response=\"70eda34f1683041fd9ab72056c51b740\",",
                        "cnonce=\"61417766e50cb980\",",
                        "opaque=\"d8ea7aa61a1693024c4cc3a516f49b3c\",",
                        "qop=\"auth\",",
                        "nc=00000001">>,
  meck:unload(erldigest_nonce_generator),
  erldigest_test_utils:assert_response_are_equivalent(Expected, Response).

another_http_example_again_test() ->
  meck:new(erldigest_nonce_generator, [passthrough, unstick, nolink]),
  meck:expect(erldigest_nonce_generator, generate_nonce, 0, {<<"00000001">>, <<"86859d0e047b826eb82a0463270916e7">>}),
  Challenge = <<"Digest realm=\"Login to 2J0085BFAG00007\",",
                        "qop=\"auth\",",
                        "nonce=\"Z2VuZXRlYy1kaWdlc3Q6NDMwNTM5ODAwMjA=\",",
                        "opaque=\"\",",
                        "stale=\"false\"">>,
  {ok, Response} = erldigest:calculate_response(<<"GET">>, <<"/api/param.cgi?req=General.Brand.CompanyName&req=Network.1.MacAddress">>, Challenge, <<"admin">>, <<"admin">>),
  Expected = <<"Digest username=\"admin\",",
                        "realm=\"Login to 2J0085BFAG00007\",",
                        "nonce=\"Z2VuZXRlYy1kaWdlc3Q6NDMwNTM5ODAwMjA=\",",
                        "uri=\"/api/param.cgi?req=General.Brand.CompanyName&req=Network.1.MacAddress\",",
                        "response=\"14c3db181791d928152fa4a870ed1a7b\",",
                        "cnonce=\"86859d0e047b826eb82a0463270916e7\",",
                        "qop=\"auth\",",
                        "nc=00000001">>,
  meck:unload(erldigest_nonce_generator),
  erldigest_test_utils:assert_response_are_equivalent(Expected, Response).

httpbin_MD5_test() ->
  application:ensure_all_started(hackney),
  Username = <<"SuperUser">>,
  Password = <<"DuperPassword">>,
  Url = <<"/digest-auth/auth/", Username/binary, "/", Password/binary>>,
  FullUrl = <<"https://httpbin.org", Url/binary>>,
  {ok, 401, RespHeaders, ClientRef} =  hackney:request(get, FullUrl),
  {ok, _} = hackney:body(ClientRef),
  Challenge = proplists:get_value(<<"Www-Authenticate">>, RespHeaders),
  {ok, ChallengeResponse} = erldigest:calculate_response(<<"GET">>, Url, Challenge, Username, Password),
  Headers = [{<<"Authorization">>, ChallengeResponse}],
  {ok, StatusCode, _, ClientRef2} =  hackney:request(get, FullUrl, Headers),
  {ok, _} = hackney:body(ClientRef2),
  ?assertEqual(200, StatusCode).

dahua_rtsp_test() ->
  Challenge = <<"Digest realm=\"Login to 2J0085BFAG00007\", nonce=\"9cfe1153903a04e8643f85cfc7defef5\"">>,
  {ok, Response} = erldigest:calculate_response(options, <<"rtsp://1.2.3.4:554/VideoInput/1/mjpeg/1">>, Challenge, <<"admin">>, <<"admin">>),
  Expected = <<"Digest username=\"admin\",",
                      "realm=\"Login to 2J0085BFAG00007\",",
                      "nonce=\"9cfe1153903a04e8643f85cfc7defef5\",",
                      "uri=\"rtsp://1.2.3.4:554/VideoInput/1/mjpeg/1\",",
                      "response=\"f03b2c4265434c631305450403e79a54\"">>,
  erldigest_test_utils:assert_response_are_equivalent(Expected, Response).
