package play

default allow := false

iss_expected := "https://sts.windows.net/e06c4271-a28e-4529-a1ae-bc119f805788/"
aud_expected := "api://3b6627d8-5cd1-4866-b512-90eeebf7bfd4"
jwks_str := sprintf("%s", [data.idp.jwks])

verified_claims := claims {
  [ok, header, claims] := io.jwt.decode_verify(input.identity, {
    "cert": jwks,
    "iss":  iss_expected,
    "aud":  aud_expected,
    "alg": "RS256"
  })
  ok
}
allow {
  verified_claims
}
