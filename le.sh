#!/usr/local/bin/bash

# shell script hardening
set -euf -o pipefail

#
# Lets Encrypt Certificate Generator
#    https://calomel.org/lets_encrypt_client.html
#    lets_encrypt.sh v0.07
#
# The script will generate a new certificate for the domain specified and
# negotiate with the Lets Encrypt ACME server to save a signed certificate
# chain.
#
# dependency: bash (/dev/fd), openssl, curl

################ options start#################

# The primary domain name followed by any alternative names we are requesting a
# certificate for. Use a space separated list. Each domain name will be tested
# by the ACME server. 
#DOMAINS="example.org www.example.org mail.example.org"
DOMAINS="example.org www.example.org"

# The directory the script is run from and where all certificates will be
# stored under. This directory should be secure and not under the web root.
BASEDIR="/tools/lets_encrypt"

# The full path to the web directory our script will write the temporary
# negotiation file. The Lets Encrypt service will then connect to our web
# server to collect this temporary file verifying we own the domain. Our web
# server can serve the file through http or https and 301 redirection are
# allowed.
WEBDIR="/var/www/.well-known/acme-challenge"

# SSL Certificates type. RSA at 2048 bit should be used for wider compatability
# including older clients. ECDSA prime 256 bits is prefered for its smaller key
# size, faster server side processing and better security model. Options: "rsa"
# or "ecdsa"
CERTTYPE="rsa"
#CERTTYPE="ecdsa"

# The Lets Encrypt certificate authority URL
CA="https://acme-staging.api.letsencrypt.org" # testing server, high rate limits. "Fake LE Intermediate X1"
#CA="https://acme-v01.api.letsencrypt.org"      # official server, rate limited to 5 certs per 7 days

################ options end ##################


# The license file the script will automatically accept for you
LICENSE="https://letsencrypt.org/documents/LE-SA-v1.1.1-August-1-2016.pdf"

# The local name of Lets Encrypt public certificate
ROOTCERT="lets-encrypt-x3-cross-signed.pem.txt"

# check the path to the openssl configuration file
OPENSSL_CNF="$(openssl version -d | cut -d'"' -f2)/openssl.cnf"


urlbase64() {
  # urlbase64: base64 encoded string with '+' replaced with '-' and '/' replaced with '_'
  openssl base64 -e | tr -d '\n\r' | sed 's/=*$//g' | tr '+/' '-_'
}

hex2bin() {
  # Store hex string from stdin
  tmphex="$(cat)"

  # Remove spaces
  hex=''
  for ((i=0; i<${#tmphex}; i+=1)); do
    test "${tmphex:$i:1}" == " " || hex="${hex}${tmphex:$i:1}"
  done

  # Add leading zero
  test $((${#hex} & 1)) == 0 || hex="0${hex}"

  # Convert to escaped string
  escapedhex=''
  for ((i=0; i<${#hex}; i+=2)); do
    escapedhex=${escapedhex}\\x${hex:$i:2}
  done

  # Convert to binary data
  printf -- "${escapedhex}"
}

_request() {
  tempcont="$(mktemp)"

  case "${1}" in
     "get" )
         statuscode="$(curl -s -w "%{http_code}" -o "${tempcont}" "${2}")" ;;
     "head" )
         statuscode="$(curl -s -w "%{http_code}" -o "${tempcont}" "${2}" -I)" ;;
     "post" )
         statuscode="$(curl -s -w "%{http_code}" -o "${tempcont}" "${2}" -d "${3}")" ;;
  esac

  if [[ ! "${statuscode:0:1}" = "2" ]]; then
    printf '%s\n' "   ERROR: sending ${1}-request to ${2} (Status ${statuscode})" >&2
    printf '%s\n' >&2
    printf '%s\n' "Details:" >&2
    printf '%s\n' "$(<"${tempcont}"))" >&2
    rm -f "${tempcont}"
    exit 1
  fi

  cat  "${tempcont}"
  rm -f "${tempcont}"
}

thumb_print() {
  # Collect the public components from the new private key and calculate the
  # thumbprint which the ACME server will challenge
  pubExponent64="$(printf "%06x" "$(openssl rsa -in "${BASEDIR}/private_account_key.pem" -noout -text | grep publicExponent | head -1 | cut -d' ' -f2)" | hex2bin | urlbase64)"
  pubMod64="$(printf '%s' "$(openssl rsa -in "${BASEDIR}/private_account_key.pem" -noout -modulus | cut -d'=' -f2)" | hex2bin | urlbase64)"
  thumbprint="$(printf '%s' "$(printf '%s' '{"e":"'"${pubExponent64}"'","kty":"RSA","n":"'"${pubMod64}"'"}' | shasum -a 256 | awk '{print $1}')" | hex2bin | urlbase64)"
}

signed_request() {
  # Encode payload as urlbase64
  payload64="$(printf '%s' "${2}" | urlbase64)"

  # Retrieve nonce from acme-server
  nonce="$(_request head "${CA}/directory" | grep Replay-Nonce: | awk -F ': ' '{print $2}' | tr -d '\n\r')"

  # Build header with the public key and algorithm information
  header='{"alg": "RS256", "jwk": {"e": "'"${pubExponent64}"'", "kty": "RSA", "n": "'"${pubMod64}"'"}}'

  # Build another header containing the previously received nonce and encode the nonce as urlbase64
  protected='{"alg": "RS256", "jwk": {"e": "'"${pubExponent64}"'", "kty": "RSA", "n": "'"${pubMod64}"'"}, "nonce": "'"${nonce}"'"}'
  protected64="$(printf '%s' "${protected}" | urlbase64)"

  # Sign the header with the nonce and the payload with the private key and the encode the signature as urlbase64
  signed64="$(printf '%s' "${protected64}.${payload64}" | openssl dgst -sha256 -sign "${BASEDIR}/private_account_key.pem" | urlbase64)"

  # Send header + extended header + payload + signature to the acme-server
  data='{"header": '"${header}"', "protected": "'"${protected64}"'", "payload": "'"${payload64}"'", "signature": "'"${signed64}"'"}'

  _request post "${1}" "${data}"
}

sign_domain() {
  domain="${1}"
  altnames="${*}"

  # create a directory to keep the domain's certificates in
  if [[ ! -e "${BASEDIR}/${domain}" ]]; then
    printf " + Make directory ${BASEDIR}/${domain}\n"
    mkdir -p "${BASEDIR}/${domain}" 
  fi

  # Create a new private key for the domain. To add a bit of entropy to the
  # process, a simple loop will randomly generate between five(5) and ten(10)
  # private keys and the last key created will be used for the certificate
  # signing request. A loop is not necessary on native hardware, but may help
  # seed virtual machine (VM) entropy.
    printf " + Seed entropy by generating random keys:"
    START=1
    END=$(( RANDOM % (10 - 5 + 1 ) + 5 ))
    for (( i=$START; i<=$END; i++ ))
      do
       printf " ${i}" 
       case "${CERTTYPE}" in
        "rsa" )
          openssl genrsa -out "${BASEDIR}/${domain}/${domain}-privatekey.pem" 2048 2> /dev/null > /dev/null ;;
        "ecdsa" )
          openssl ecparam -genkey -name prime256v1 -out "${BASEDIR}/${domain}/${domain}-privatekey.pem" 2> /dev/null > /dev/null ;;
       esac
      done
    printf "\n + Private Key created\n"

  # Generate a signing request
  SAN=""
  for altname in ${altnames}; do
    SAN+="DNS:${altname}, "
  done
  SAN="${SAN%%, }"
  printf " + Generate signing request\n"
  openssl req -new -sha256 -key "${BASEDIR}/${domain}/${domain}-privatekey.pem" -out "${BASEDIR}/${domain}/${domain}-certsignrequest.csr" -subj "/CN=${domain}/" -reqexts SAN -config <(cat "${OPENSSL_CNF}" <(printf "[SAN]\nsubjectAltName=%s" "${SAN}")) > /dev/null

  # Request and respond to challenges
  for altname in ${altnames}; do
    # Ask the acme-server for new challenge token and extract them from the resulting json block
    printf " + Request challenge for ${altname}\n"
    response="$(signed_request "${CA}/acme/new-authz" '{"resource": "new-authz", "identifier": {"type": "dns", "value": "'"${altname}"'"}}')"

    challenges="$(printf '%s\n' "${response}" | grep -Eo '"challenges":[^\[]*\[[^]]*]')"
    challenge="$(printf "%s" "${challenges//\{/$'\n'{}}" | grep 'http-01')"
    challenge_token="$(printf '%s' "${challenge}" | grep -Eo '"token":\s*"[^"]*"' | cut -d'"' -f4 | sed 's/[^A-Za-z0-9_\-]/_/g')"
    challenge_uri="$(printf '%s' "${challenge}" | grep -Eo '"uri":\s*"[^"]*"' | cut -d'"' -f4)"

    if [[ -z "${challenge_token}" ]] || [[ -z "${challenge_uri}" ]]; then
      printf "    Error: Can't retrieve challenges (${response})\n"
      exit 1
    fi

    # Challenge response consists of the challenge token and the thumbprint of our public certificate
    keyauth="${challenge_token}.${thumbprint}"

    # Store challenge response in the web directory 
    printf '%s' "${keyauth}" > "${WEBDIR}/${challenge_token}"
    chmod a+r "${WEBDIR}/${challenge_token}"

    # Request the acme-server to verify our challenge and wait until the request is valid
    printf " + Respond to challenge for ${altname}\n"
    result="$(signed_request "${challenge_uri}" '{"resource": "challenge", "keyAuthorization": "'"${keyauth}"'"}')"

    status="$(printf '%s\n' "${result}" | grep -Eo '"status":\s*"[^"]*"' | cut -d'"' -f4)"

    # Loop until the status of the request is accepted    
    while [[ "${status}" = "pending" ]]; do
      sleep 1
      status="$(_request get "${challenge_uri}" | grep -Eo '"status":\s*"[^"]*"' | cut -d'"' -f4)"
    done

    # Remove the temporary challenge file from the web directory
    rm -f "${WEBDIR}/${challenge_token}"

    # Check the status of the ACME server negotiation
    if [[ "${status}" = "valid" ]]; then
      printf " + Challenge accepted\n"
    else
      printf "   Challenge is invalid ! (returned: ${status})\n"
      exit 1
    fi

  done

  # create domain certificate
  printf " + Create domain certificate\n"
  csr64="$(openssl req -in "${BASEDIR}/${domain}/${domain}-certsignrequest.csr" -outform DER | urlbase64)"
  crt64="$(signed_request "${CA}/acme/new-cert" '{"resource": "new-cert", "csr": "'"${csr64}"'"}' | openssl base64 -e)"
  printf -- '-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n' "${crt64}" > "${BASEDIR}/${domain}/${domain}-certchain.pem"

  # add the intermediate lets encrypt public certificate to the chain 
  printf " + Add intermediate certificate to chain\n"
  cat "${BASEDIR}/${ROOTCERT}" >> "${BASEDIR}/${domain}/${domain}-certchain.pem"

  printf " + Complete.\n"
  
}

inspect() {
  domain="${1}"

  rootcerts="/etc/ssl/" 
  # location of FreeBSD's root certificates
  if [ -f /etc/ssl/cert.pem ]; then
     rootcerts="/etc/ssl/cert.pem"
  fi

  printf "\n\n     Certificate Inspection\n"
  printf "    ------------------------\n"

  case "${CERTTYPE}" in
  "rsa" )
     printf "\nMD5 signatures must be equal\n\n"
     md5privatekey="$(openssl rsa -noout -modulus -in ${BASEDIR}/${domain}/${domain}-privatekey.pem | openssl md5)" 
     md5certsignrequest="$(openssl req -noout -modulus -in ${BASEDIR}/${domain}/${domain}-certsignrequest.csr | openssl md5)"
     md5certchain="$(openssl x509 -noout -modulus -in ${BASEDIR}/${domain}/${domain}-certchain.pem | openssl md5)" 
     printf "   Private Key   = ${md5privatekey}\n"
     printf "   Cert Sign Req = ${md5certsignrequest}\n"
     printf "   Cert Chain    = ${md5certchain}\n" ;;

  "ecdsa" )
    #md5privatekey="$(openssl ec -noout -modulus -in ${BASEDIR}/${domain}/${domain}-privatekey.pem | openssl md5)" ;;
  esac


  printf "\nLocally Inspect Certificate\n   openssl x509 -in ${domain}/${domain}-certchain.pem -text -noout\n"
  printf "\nRemotely Inspect Certificate\n   openssl s_client -CApath ${rootcerts} -connect ${domain}:443 \n"


  case "${CERTTYPE}" in
  "rsa" )
  hpkp="$(openssl rsa -in ${BASEDIR}/${domain}/${domain}-privatekey.pem -outform der -pubout 2>/dev/null | openssl dgst -sha256 -binary | openssl enc -base64)" ;;
  "ecdsa" )
  hpkp="$(openssl ec -in ${BASEDIR}/${domain}/${domain}-privatekey.pem -outform der -pubout 2>/dev/null | openssl dgst -sha256 -binary | openssl enc -base64)" ;;
  esac

  printf "\nHTTP Key Pinning\n   pin-sha256=\"${hpkp}\";\n"

  # check the issuer field and the full certificate path against the system's root certificate chain
  printf "\nVerify the authority and certificate chain\n" 
  printf "   "; openssl x509 -noout -in ${domain}/${domain}-certchain.pem -issuer
  printf "   "; openssl verify -CApath ${rootcerts} ${ROOTCERT}
  printf "   "; openssl verify -CApath ${rootcerts} -untrusted ${ROOTCERT} ${domain}/${domain}-certchain.pem
  printf "\n\n"

}


##
## Lets Encrypt main()
##

printf "\n     Lets Encrypt Certificate Generator\n"
printf "    ------------------------------------\n"
printf "\nInitialize the environment\n\n"

# Change directory to BASEDIR
  cd ${BASEDIR}

# Update the Lets Encrypt Authority PEM certificate
  printf " + Update the Lets Encrypt Authority PEM certificate\n"
  curl -sS -L -o ${BASEDIR}/${ROOTCERT} https://letsencrypt.org/certs/${ROOTCERT}

# Generate a new account key 
  printf " + Generate new private account key\n"
  openssl genrsa -out "${BASEDIR}/private_account_key.pem" "4096" 2> /dev/null > /dev/null

# Calculate the thumbprint to be registered with the ACME server
  printf " + Calculate key thumbprint for ACME challenge\n"
  pubExponent64=""; pubMod64=""; thumbprint=""
  thumb_print

# Register the new account key with the Lets Encrypt ACME service
  printf " + Register private account key with ACME server\n"
  signed_request "${CA}/acme/new-reg" '{"resource": "new-reg", "agreement": "'"${LICENSE}"'"}' > /dev/null

# Generate certificate for the domain
  printf "\nGenerate certificate for ${DOMAINS}\n\n"
  sign_domain ${DOMAINS}

# Visually inspect the MD5 hashes
  inspect ${DOMAINS} 


#
##
### EOF ###
