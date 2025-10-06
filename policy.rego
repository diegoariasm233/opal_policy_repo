package play

default allow := false

tenant_id := "e06c4271-a28e-4529-a1ae-bc119f805788"
iss_expected := sprintf("https://sts.windows.net/%s/", [tenant_id])
aud_expected := "api://3b6627d8-5cd1-4866-b512-90eeebf7bfd4"

jwks_str := sprintf("%s", [data.idp.jwks])
token := t {
  parts := split(input.identity, " ")
  lower(parts[0]) == "bearer"
  t := parts[1]
} else := t {
  t := input.identity
}

verified_claims := claims {
  [valid, header, claims] := io.jwt.decode_verify(token, {
    "cert": jwks_str,
    "iss":  iss_expected,
    "aud":  aud_expected,
    "alg":  "RS256"
  })
  valid == true
  claims.tid == tenant_id
}

allow {
  verified_claims
}
