HandshakeFail="handshake failure"
NoCipherMatch="no cipher match"
certsCount=0
raw_certificates=()
prevIp=""

CipherSuite=(
  'EXP-EDH-DSS-DES-CBC-SHA'
  'EXP-EDH-RSA-DES-CBC-SHA'
  'EXP-ADH-DES-CBC-SHA'
  'EXP-DES-CBC-SHA'
  'EXP-RC2-CBC-MD5'
  'EXP-KRB5-RC2-CBC-SHA'
  'EXP-KRB5-DES-CBC-SHA'
  'EXP-KRB5-RC2-CBC-MD5'
  'EXP-KRB5-DES-CBC-MD5'
  'EXP-ADH-RC4-MD5'
  'EXP-RC4-MD5'
  'EXP-KRB5-RC4-SHA'
  'EXP-KRB5-RC4-MD5'
  'EXP-RC2-MD5'
  'EXP1024-DES-CBC-SHA'
  'EXP1024-RC4-SHA'
  'EXP1024-DHE-DSS-DES-CBC-SHA'
  'EXP1024-DHE-DSS-RC4-SHA'
)

function join_cipher_by_colon() {
  if (( $# >= 3 )); then
    local IFS=$1
  fi
  shift
  joinedCiphers="$*"
}

#Join the weak ciphers by ':'
join_cipher_by_colon ':' "${CipherSuite[@]}"

function parse_ssl_output() {
  currProtocol=""
  while read line;
  do
    if [[ $line =~ ^Protocol\ + ]]; then
      local match=($line)
      currProtocol="${match[2]}"
      continue
    fi

    if [[ $line =~ New,\  ]]; then
      local match=($line)
      currCipher="${match[4]}"
      continue
    fi

    if [[ $line =~ -----BEGIN\ CERTIFICATE----- ]]; then
      currCertificate="$line"$'\n'
      while read data;
      do
        currCertificate+="$data"$'\n'
        if [[ $data =~ -----END\ CERTIFICATE----- ]]; then
          break
        fi
      done

      #Checks if the currently read certificate is in the certificates array. If not, adds it to the array
      if [[ " ${raw_certificates[@]} " =~ " ${currCertificate} " ]]; then
        CertificateSharing="YES"
      else
        raw_certificates[$certsCount]=$currCertificate
        certsCount=$((certsCount+1))
      fi
    fi
  done
}

#Scans the host ==> Takes the server name and ip address as input
function scan_host() {
  cmnd="timeout 20 openssl s_client -connect $2:443"  
  for tls_version in "-tls1_2" "-tls1_1" "-tls1" "-ssl3" "-ssl2"
  do
    if [[ "$tls_version" != "-ssl2" && $TlsVersion -ne 0 && "$prevIp" == $2 ]]; then
        continue
    fi

    if [[ "$tls_version" == "-ssl2" ]]; then
      sslCmnd="$cmnd -ssl2"
    else
      sslCmnd="$cmnd -servername $1 $tls_version"
    fi
    local output=$(echo "O" | $sslCmnd 2>&1)
    if ! [[ $output =~ $HandshakeFail ]]; then
      parse_ssl_output <<<"$output"
      if [[ "$currCipher" != "(NONE)" ]]; then
        SSLSupport="YES"
        case "$tls_version" in
          -tls1_2)
            currVersion=12
            ;;
          -tls1_1)
            currVersion=11
            ;;
          -tls1)
            currVersion=10
            ;;
          -ssl3)
            currVersion=3
            ;;
          -ssl2)
            currVersion=2
            ;;
          *)
            currVersion=0
            ;;
        esac
        
        if [[ $currVersion -gt $TlsVersion ]]; then
          TlsVersion=$currVersion
        fi
      
        if [[ "$tls_version" == "-ssl2" ]]; then
          Sslv2Support="YES"

          #Check for weak ciphers
          sslCmnd="$sslCmnd -cipher $joinedCiphers"
          local weakCipOutput=$(echo "O" | $sslCmnd 2>&1)
          if ! [[ $weakCipOutput =~ $HandshakeFail || $weakCipOutput =~ $NoCipherMatch ]]; then
            WeakCiphers="YES"
          fi
        fi
        prevIp=$2
        sleep 1
      fi
    fi
  done
}

#Prints the usage information
function usage() {
    echo -e "USAGE: hostScan [-s|--server target]

Scans the given host to get the highest version of SSL suported.
Also checks if the server is vulnerable to DROWN attack.
The port number for the given target defaults to 443.

EXAMPLE: 
hostScan -s google.com
hostScan --server google.com"
}

#If no arguments are specified, call usage and exit
if [[ $# == 0 ]]; then
  usage
  exit 1
fi

while :
do
  case $1 in 
    #Check if the option passed is -s or --server and store the target in HOST variable
    -s | --server)
      TARGET=$2
      shift 2
      ;;
    -r | --rank)
      RANK=$2
      shift
      ;;
    --)
      shift
      break
      ;;
    #For all other arguments passed, print usage and exit
    *)
      break
      ;;
  esac
done

TopDomain="${TARGET#*.}"

#Get all the ips associated with the given target
host_result=$(host $TARGET | awk '/has address/ {print $4}')

#Get all ips associated with given www.target
wwwHost_result=$(host www.$TARGET | awk '/has address/ {print $4}')

#Split the ip's returned by host and store them in an array
ipv4_arr=$(echo $host_result | tr " " "\n")
ipv4_arr_www=$(echo $wwwHost_result | tr " " "\n")

#Add the www addresses to ipv4  arrays if the ips are not in the initial array
for ipVal in ${ipv4_arr_www[@]}
do
  if ! [[ " ${ipv4_arr[@]} " =~ " ${ipVal} " ]]; then
    ipv4_arr=(${ipv4_arr[@]} $ipVal)
  fi
done

SSLSupport="NO"
CertificateSharing="NO"
TlsVersion=0
Sslv2Support="NO"
WeakCiphers="NO"
DrownVulnerable="NO"

for ip in ${ipv4_arr[@]}
do
  #Check if port 443 is open for given ip. If yes, then test for other cases
  ./tcping -u 5000000 $ip 443
  if [ $? -gt 0 ]; then
    continue
  fi
  scan_host $TARGET $ip
done

#Clear the certificates array
unset raw_certificates

if [[ "$Sslv2Support" == "YES" && "$CertificateSharing" == "YES" ]]; then
  DrownVulnerable="YES"
fi

if [[ "$WeakCiphers" == "YES" ]]; then
  DrownVulnerable="YES"
fi

#Save the version of TLS based on the version number obationed
case $TlsVersion in
  12)
    HighestVersion="TLSv1.2"
    ;;
  11)
    HighestVersion="TLSv1.1"
    ;;
  10)
    HighestVersion="TLSv1.0"
    ;;
  3)
    HighestVersion="SSLv3"
    ;;
  2)
    HighestVersion="SSLv2"
    ;;
  *)
    HighestVersion="NoTLS"
    ;;
esac

echo "$RANK, $TopDomain, $TARGET, $SSLSupport, $HighestVersion, $Sslv2Support, $WeakCiphers, $CertificateSharing, $DrownVulnerable"
