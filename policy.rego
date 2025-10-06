package play

default allow := false

iss_expected := "https://sts.windows.net/e06c4271-a28e-4529-a1ae-bc119f805788/"
aud_expected := "api://3b6627d8-5cd1-4866-b512-90eeebf7bfd4"
jwks := data.idp.jwks

token := t {
  some parts
  parts := split(input.identity, " ")
  lower(parts[0]) == "bearer"
  t := parts[1]
} else := t { t := input.identity }

verified_claims := claims {
  [ok, header, claims] := io.jwt.decode_verify(token, {
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
