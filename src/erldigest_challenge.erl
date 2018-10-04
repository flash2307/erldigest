-module(erldigest_challenge).

-export([parse/1,
         make_challenge/1,
         get_value/2]).

%%%===================================================================
%%% API
%%%===================================================================

parse(<<"Digest ", Challenge/binary>>) ->
  Regex = <<"([^=]+)=((?:[^\"]*)|(?:\"[^\"]*\"))(?:\\s*,\\s*|\\s*$)">>,
  {match, Captures} = re:run(Challenge,  Regex, [global]),
  Fields = extract_fields(Captures, Challenge),
  {ok, Fields};
parse(_) ->
  {error, invalid_challenge}.

make_challenge(Options) ->
  Fields = make_challenge_fields(Options),
  {ok, <<"Digest ", Fields/binary>>}.

-spec get_value(Name::atom(), Challenge::binary()) -> {ok, Value::binary()}.
get_value(Name, Challenge) ->
  ParsedChallenge = erldigest_challenge:parse(Challenge),
  maps:get(Name, ParsedChallenge).


%%%===================================================================
%%% Internal Functions
%%%===================================================================

extract_fields(Captures, Challenge) ->
  extract_fields(Captures, Challenge, #{}).
extract_fields([Head | Tail], Challenge, Fields) ->
  [_, {KeyBegin, KeyLength}, {ValueBegin, ValueLength}] = Head,
  Key = get_atom_key(binary:part(Challenge, KeyBegin, KeyLength)),
  Value = erldigest_utils:remove_surrounding_quotes(binary:part(Challenge, ValueBegin, ValueLength)),
  extract_fields(Tail, Challenge, Fields#{Key => Value});
extract_fields([], _, Fields) ->
  Fields.

get_atom_key(BinaryKey) ->
  case BinaryKey of
    <<"realm">> -> realm;
    <<"domain">> -> domain;
    <<"nonce">> -> nonce;
    <<"opaque">> -> opaque;
    <<"stale">> -> stale;
    <<"algorithm">> -> algorithm;
    <<"qop">> -> qop;
    <<"username">> -> username;
    <<"uri">> -> uri;
    <<"response">> -> response;
    <<"cnonce">> -> cnonce;
    <<"nc">> -> nc
  end.

make_challenge_fields(Options) ->
  Keys = [username, realm, nonce, uri, response, algorithm, cnonce, opaque, qop, nc],
  Fields = lists:foldl(fun(Key, Acc) ->
                         BinaryKey = atom_to_binary(Key, latin1),
                         Value = maps:get(Key, Options, <<>>),
                         Field = make_challenge_field(BinaryKey, Value),
                         <<Acc/binary, Field/binary>>
                       end, <<>>, Keys),
  binary:part(Fields, 0, byte_size(Fields)-1).

make_challenge_field(_, <<>>) ->
  <<>>;
make_challenge_field(<<"nc">>, NonceCount) ->
  <<"nc=", NonceCount/binary, ",">>;
make_challenge_field(Key, Value) ->
  <<Key/binary, "=\"", Value/binary, "\",">>.
