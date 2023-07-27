/*
Copyright The Ratify Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package azurekeyvault

// This class is based on implementation from  azure secret store csi provider
// Source: https://github.com/Azure/secrets-store-csi-driver-provider-azure/tree/release-1.4/pkg/provider
import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	kv "github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/deislabs/ratify/pkg/certificateprovider/azurekeyvault/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestParseAzureEnvironment(t *testing.T) {
	envNamesArray := []string{"AZURECHINACLOUD", "AZUREGERMANCLOUD", "AZUREPUBLICCLOUD", "AZUREUSGOVERNMENTCLOUD", ""}
	for _, envName := range envNamesArray {
		azureEnv, err := parseAzureEnvironment(envName)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if strings.EqualFold(envName, "") && !strings.EqualFold(azureEnv.Name, "AZUREPUBLICCLOUD") {
			t.Fatalf("string doesn't match, expected AZUREPUBLICCLOUD, got %s", azureEnv.Name)
		} else if !strings.EqualFold(envName, "") && !strings.EqualFold(envName, azureEnv.Name) {
			t.Fatalf("string doesn't match, expected %s, got %s", envName, azureEnv.Name)
		}
	}

	wrongEnvName := "AZUREWRONGCLOUD"
	_, err := parseAzureEnvironment(wrongEnvName)
	if err == nil {
		t.Fatalf("expected error for wrong azure environment name")
	}
}

func TestFormatKeyVaultCertificate(t *testing.T) {
	cases := []struct {
		desc                   string
		keyVaultObject         types.KeyVaultCertificate
		expectedKeyVaultObject types.KeyVaultCertificate
	}{
		{
			desc: "leading and trailing whitespace trimmed from all fields",
			keyVaultObject: types.KeyVaultCertificate{
				CertificateName:    "cert1     ",
				CertificateVersion: "",
			},
			expectedKeyVaultObject: types.KeyVaultCertificate{
				CertificateName:    "cert1",
				CertificateVersion: "",
			},
		},
		{
			desc: "no data loss for already sanitized object",
			keyVaultObject: types.KeyVaultCertificate{
				CertificateName:    "cert1",
				CertificateVersion: "version1",
			},
			expectedKeyVaultObject: types.KeyVaultCertificate{
				CertificateName:    "cert1",
				CertificateVersion: "version1",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			formatKeyVaultCertificate(&tc.keyVaultObject)
			if !reflect.DeepEqual(tc.keyVaultObject, tc.expectedKeyVaultObject) {
				t.Fatalf("expected: %+v, but got: %+v", tc.expectedKeyVaultObject, tc.keyVaultObject)
			}
		})
	}
}

func SkipTestInitializeKVClient(t *testing.T) {
	testEnvs := []azure.Environment{
		azure.PublicCloud,
		azure.GermanCloud,
		azure.ChinaCloud,
		azure.USGovernmentCloud,
	}

	for i := range testEnvs {
		kvBaseClient, err := initializeKvClient(context.TODO(), testEnvs[i].KeyVaultEndpoint, "", "")
		assert.NoError(t, err)
		assert.NotNil(t, kvBaseClient)
		assert.NotNil(t, kvBaseClient.Authorizer)
		assert.Contains(t, kvBaseClient.UserAgent, "ratify")
	}
}

func TestGetCertificates(t *testing.T) {
	cases := []struct {
		desc        string
		parameters  map[string]string
		secrets     map[string]string
		expectedErr bool
	}{
		{
			desc:        "keyvault uri not provided",
			parameters:  map[string]string{},
			expectedErr: true,
		},
		{
			desc: "tenantID not provided",
			parameters: map[string]string{
				"vaultUri": "https://testkv.vault.azure.net/",
			},
			expectedErr: true,
		},
		{
			desc: "clientID not provided",
			parameters: map[string]string{
				"vaultUri": "https://testkv.vault.azure.net/",
				"tenantID": "tid",
			},
			expectedErr: true,
		},
		{
			desc: "invalid cloud name",
			parameters: map[string]string{
				"vaultUri":  "https://testkv.vault.azure.net/",
				"tenantID":  "tid",
				"cloudName": "AzureCloud",
			},
			expectedErr: true,
		},
		{
			desc: "certificates array not set",
			parameters: map[string]string{
				"vaultUri":             "https://testkv.vault.azure.net/",
				"tenantID":             "tid",
				"useVMManagedIdentity": "true",
			},
			expectedErr: true,
		},
		{
			desc: "certificates not configured as an array",
			parameters: map[string]string{
				"vaultUri":             "https://testkv.vault.azure.net/",
				"tenantID":             "tid",
				"useVMManagedIdentity": "true",
				"certificates": `
        - |
          CertificateName: cert1
          CertificateVersion: ""`,
			},
			expectedErr: true,
		},
		{
			desc: "certificates array is empty",
			parameters: map[string]string{
				"vaultUri": "https://testkv.vault.azure.net/",
				"tenantID": "tid",
				"clientID": "clientid",
				"certificates": `
      array:`,
			},
			expectedErr: true,
		},
		{
			desc: "invalid object format",
			parameters: map[string]string{
				"vaultUri": "https://testkv.vault.azure.net/",
				"tenantID": "tid",
				"clientID": "clientid",
				"certificates": `
      array:
        - |
          CertificateName: cert1
          CertificateVersion: ""`,
			},
			expectedErr: true,
		},
		{
			desc: "error fetching from keyvault",
			parameters: map[string]string{
				"vaultUri": "https://testkv.vault.azure.net/",
				"tenantID": "tid",
				"certificates": `
      array:
        - |
          CertificateName: cert1
          CertificateVersion: ""`,
			},
			expectedErr: true,
		},
	}

	provider := Create()

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			certs, certStatus, err := provider.GetCertificates(context.TODO(), tc.parameters)
			if tc.expectedErr {
				assert.NotNil(t, err)
				assert.Nil(t, certs)
				assert.Nil(t, certStatus)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestGetCertStatusMap(t *testing.T) {
	certsStatus := []map[string]string{}
	certsStatus = append(certsStatus, map[string]string{
		"CertName":    "Cert1",
		"CertVersion": "VersionABC",
	})
	certsStatus = append(certsStatus, map[string]string{
		"CertName":    "Cert2",
		"CertVersion": "VersionEDF",
	})

	actual := getCertStatusMap(certsStatus)
	assert.NotNil(t, actual[types.CertificatesStatus])
}

func TestGetObjectVersion(t *testing.T) {
	id := "https://kindkv.vault.azure.net/secrets/cert1/c55925c29c6743dcb9bb4bf091be03b0"
	expectedVersion := "c55925c29c6743dcb9bb4bf091be03b0"
	actual := getObjectVersion(id)
	assert.Equal(t, expectedVersion, actual)
}

func TestGetCertStatusProperty(t *testing.T) {
	timeNow := time.Now().String()
	certName := "certName"
	certVersion := "versionABC"

	status := getCertStatusProperty(certName, certVersion, timeNow)
	assert.Equal(t, certName, status[types.CertificateName])
	assert.Equal(t, timeNow, status[types.CertificateLastRefreshed])
	assert.Equal(t, certVersion, status[types.CertificateVersion])
}

func TestGetKeyvaultRequestObj(t *testing.T) {
	attrib := map[string]string{}
	attrib["vaultURI"] = "https://testvault.vault.azure.net/"
	attrib["clientID"] = "TestClient"
	attrib["cloudName"] = "TestCloud"
	attrib["tenantID"] = "TestIDABC"
	attrib["certificates"] = "array:\n- |\n  certificateName: wabbit-networks-io  \n  certificateVersion: \"testversion\"\n"

	result, err := getKeyvaultRequestObj(attrib)

	if err != nil {
		logrus.Infof("err %v", err)
	}

	assert.Equal(t, "wabbit-networks-io", result[0].CertificateName)
	assert.Equal(t, "testversion", result[0].CertificateVersion)
}

func TestGetCertFromSecretBundle(t *testing.T) {

	// PEM
	secretForTesting := getSecretBundlePem()
	cert, status, _ := getCertFromSecretBundle(secretForTesting, "certName")
	assert.Equal(t, len(cert), 1)
	assert.Equal(t, len(status), 1)

	// PkcS
	secretForTesting = getSecretBundlePkcs()
	cert, status, _ = getCertFromSecretBundle(secretForTesting, "certName")
	assert.Equal(t, len(cert), 1)
	assert.Equal(t, len(status), 1)

	// Other content
	secretForTesting = getSecretBundleText()
	cert, status, err := getCertFromSecretBundle(secretForTesting, "certName")
	assert.Equal(t, err.Error(), "secret content type is invalid, expected type are application/x-pkcs12 or application/x-pem-file")
}

func TestGetKeyvaultRequestObj_error(t *testing.T) {
	cases := []struct {
		desc        string
		attrib      map[string]string
		expectedErr bool
	}{
		{
			desc: "certificates is not set",
			attrib: map[string]string{
				"certificates": "",
			},
			expectedErr: true,
		},
		{
			desc: "unexpected certificate string",
			attrib: map[string]string{
				"certificates": "certificateName: wabbit-networks-io  \n  certificateVersion: \"testversion\"\n",
			},
			expectedErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			_, err := getKeyvaultRequestObj(tc.attrib)
			if tc.expectedErr {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func getSecretBundlePkcs() kv.SecretBundle {

	value := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCoaEzK1MSiNlQh\nyKXkXccmUJlVK81GND2JOMwhqIZbgctUMIEMHh/ici5o5LilNBcYw4/sO0wt0PSU\n2q8n4JIXsXSBj6wsAHS8Hm+Llm7yz004YvFO70LzaaM5SZK8ZKroHw/6PQIo88Sa\nYiZ888f/7rHR3/5V34tCnLyNIrJLZg+V3ds8EPPtVe+Y7AConZ4N6x9RwirL4L81\nruAZyoC5fpoTKXHoqDlRbrOLmZf2nQ1EwdIpyLlb9Fnw+Wef9+fZFR0Ly/WI9kPg\nhYC3fjtL+s/XRTGXOCKWWrGAWVgeVUqN+vnYxBJHwTKtPcKkvgXk8FBQlXWr283t\naCniNe5lAgMBAAECggEAMyIwJuoBpmsukm91B2j9/gE8/WJmWqmkAZVQTev4l7JK\nRY7QsBg5gC1BMDI6albtqGRAv+6lS8gFa2kXA9mpIi6MfIZeNaIRz8jB/7U2jN0q\nyjMop9n4DyaFG/Dd7/v09LPxyv5ZOIwDpwikPQ5cLLaSIXKMrBBLHXevvH7Leh7N\nsb42U3tDu31Q7prLfKxkyXnYhaXkUKMgI/DiKVHzt6EO6Djac5fakhUslJg5GGIW\nvof80QVdrKVDvMfgRtlbgTHwiblfjYQd+4iRJ67kmewGHEMSqDF/RwPHWUN/EoDc\nc9fspeghTFXMIJHse7jdl9VqFaELhFdSyp5/EEjyhQKBgQDfVY7b+W2/108Ps3qh\nA5Qw3M/0PNzj4IzYkI2TA+gc8lxslIJJusVNTm100bNSJop9KUO0ZXO9rqLjTIwK\nH1pHGm7k/tK+nl7jK3MS8mqT1AcBN2IB2PcjlIAqheHYUR+2385CYnUOLqBDEs5N\ncsMNvc7yNXqp5PVfWwtN/qv8HwKBgQDBChV9ZHOwvOXRrnYlNLoo14g2N2GaxCyJ\neeC0bVoPKFGAQ6uPm5uYr6fw1O5rk5eImWE63gvz3irTNIUTG5rOUXVmWyRmDhcL\nFSP3vk8mp23OIcuoUraxEI68LKr7AmgjA0WG35KbHTFYf95aZu2V8g/vxn136wo1\nK0JZK7LE+wKBgHlQEUS+DXaKrwB5XqA9wG52U2N4+Ae0Pu2YP77e/WNT5w538Pm5\nwVjHxD8TdZOnKczo8ET6Ys9jIEnVl7Ab7b73xcsP/Evc3PAK9vwQwAHCx3dKrSsR\nvtUN4jy28sG89zwv/+shbjIg857bhUKelwNM2i/JCvNkUkDUxKQ+NQ/DAoGBAJeW\nW5nEMDUxoScvYQeGiElaN1Sb2MG4G2E5nAMTfA07FAUtHqP/Bgi4p6CvFSrVE8Ho\n8DlR9QDkDa0dKQMAQmiR/ycJm2Oo3N+PEleR0oYAJHIih9L+YQhagDu0t++0zCHy\nh76KAo5cNkvQ3cMP4LJHC8y2igCJSdLGzatIbXHRAoGAao6aPufQVea2W8ctXg3l\nDtk07JmSYqrSJf0BeuPjQ+5SFgXPtBUvbvUP8CDRfvmAEEF+Ns6ETBXnyr4y19Dq\nuP61wWOMsTqyFjMJD3hmcG+O4ebQRysS8u4vR6rFOOrPbYNNPcjj31/wdXliq9iq\nOIybAgnDqN/6DFRRBvzJnm0=\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nMIIDOjCCAiKgAwIBAgIQNd/dIJWDTl2vT/87QCN/QjANBgkqhkiG9w0BAQsFADAa\nMRgwFgYDVQQDEw9zdXNhbmRvbWFpbi5jb20wHhcNMjMwNjIxMDM1ODA2WhcNMjQw\nNjIxMDQwODA2WjAaMRgwFgYDVQQDEw9zdXNhbmRvbWFpbi5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCoaEzK1MSiNlQhyKXkXccmUJlVK81GND2J\nOMwhqIZbgctUMIEMHh/ici5o5LilNBcYw4/sO0wt0PSU2q8n4JIXsXSBj6wsAHS8\nHm+Llm7yz004YvFO70LzaaM5SZK8ZKroHw/6PQIo88SaYiZ888f/7rHR3/5V34tC\nnLyNIrJLZg+V3ds8EPPtVe+Y7AConZ4N6x9RwirL4L81ruAZyoC5fpoTKXHoqDlR\nbrOLmZf2nQ1EwdIpyLlb9Fnw+Wef9+fZFR0Ly/WI9kPghYC3fjtL+s/XRTGXOCKW\nWrGAWVgeVUqN+vnYxBJHwTKtPcKkvgXk8FBQlXWr283taCniNe5lAgMBAAGjfDB6\nMA4GA1UdDwEB/wQEAwIFoDAJBgNVHRMEAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMB\nBggrBgEFBQcDAjAfBgNVHSMEGDAWgBQFY45Xmcf23SDoBnpA+DBjKFMYYTAdBgNV\nHQ4EFgQUBWOOV5nH9t0g6AZ6QPgwYyhTGGEwDQYJKoZIhvcNAQELBQADggEBABpX\nrJCwD3AfNHkwlPK5f+3y7JDDbIxOiRbFi/d14S+MrDSHYdW/wpWurnhNmeOq3GWJ\nGU13PKMqI5s7lkMpSJ3k6ePlln2lq5Da+eQzyhw1XlMGgUIbf0hAjlifJ8OEcm8i\nJ9tSfbjQ04kN1fDABNRGTcBuEwGXMcxO3x9UTIDwtOSjmhlWhRVtxNm8Cm5UEgR3\nnjnYTcC+Q/nCSKN8WCEFCVJ1OAiVXXKlemJcwyqhatfZJfMqON5hmuckgtYmXsrV\nZAwTnamMAegQ7MPxKe2yKmLiqPypUv+1R2Wupjah1xUdajXiKQHR1gbaXwzAmBP4\n9tq6ty8IL8CuwARk3HY=\n-----END CERTIFICATE-----\n"
	contentType := "application/x-pkcs12"
	id := "https://notarycerts.vault.azure.net/secrets/TestCertCreatedFromPortal/87630e43dfc9465b857d65b930ed277f"
	test := kv.SecretBundle{
		Value:       &value,
		ID:          &id,
		ContentType: &contentType,
	}

	return test
}

func getSecretBundlePem() kv.SecretBundle {

	value := "-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC2yQbUFS3gXDaV\nubncpvBlvWGcuZZ3BGi1nLOeGGT/KtQNyre4XqSXCmT8TYgp9Qoijp2gdKRdoRld\nHrxS1fKC8DjB2DvFnqQqlfLSC75HEYToIa0MdPIMPMhO740GOjbVlKzIalAl4gp+\n1QId3B3KAp/QJ0nHwDb0YFGkcYKYlp2a3u1PM6diOZu49Ut6omj8TH2pdwZlvGjG\nfGvk0KhwV4rH4Rsuj6T8qN0UHY8qeGDPEBowww/p5c+vyXkCXOQLzcSY+822965o\nFtqZ2UWQP7ndNl5mXG3cYh2r3cjD9SltD+m+FuvO0xP5RUSSbXmxKF9fxecvay3k\nDifRX7rpAgMBAAECggEBALBUIWg6vjTwACBUOL5ptQMQvLeqOUK7WB/K+WOL+PJH\naKWdZ7pOYszqVB0o1jBTmOFZXypJG77PCF7Spa3rgrVZ9AbcCF1N+uSyHrsOZRK+\nDc65neykbFPt1vZ/FTZqtjc34667EHJbKvDLn+0aSQp1maH+JKiz/s+kk13luqxj\nDm8zetE9H/cj9ygsM9Rd9ul6OG+REKTjmfSAFaT7rHHcIqwPT3AKiGbnrbOPnjT4\nyR7wNMA2LsuxOeFKlcPvy8bT/3wViCKewHEKdSE6AvnyZkcBkCe2t6gMoijOP3Gf\nFNIeZ24uw0Pi5oXFBWvYzTp27FZ4AHo4um4g8DiQJgECgYEA2NvYutPhH+souA/i\noqDK4aDQGylXyNYUp5Xdbw24Ul56Xyvq3J+vF8Y/+vhcZIfg7HtBZXh7O+PJJeQB\nSfHyS7yJif5EghRpO/Wu81I6RY8+5gcFWHNumHmnP0miqdcZ3xT7ZHpZkBooFyqm\nUP+xVbaAm3+wrc6AIHxDq2zeKiECgYEA18bIagBz9ngs/V1GJkTvxTMJo2LXDuPW\ncFOXCM4ucoFca0lZhneDZLTVj9sGw/oRKFEEJhrBAE6DEeIdmAi5geP+0u+RQZN7\nTEvDuRJBfIabGAk+qASautX6T6J5ab08UOxZg1fIVXehFu4TvhAv4yVbmqYKOw/p\noetcYtgRx8kCgYEAx4GyqWbmVVweMQAETAPLwroU2vg1F8LEa803U8T2j2j2AfrA\nbsrF5gRwti6pqZ9McaOPbY/jKB0O4DocaXAarky86GQxmM64Zf5IPvimPXpkrnFF\nHLPNyp8ZG+NdsA0Bcze1dCIPpcA6o92L9zbVafql5OkbnTs+qyRHiT12QqECgYAR\nkYXP26mVb8N5/ZYwl3xOOhGW0/1eoP5ctvGdLexqNk4oDhjT8fcow/B/ff3XBw1O\nkwobcCI2vC2/zwFJ16wC/2VIF2lkRXXMiH6vGuVqFiuakWYgl/9hJvrycPAhw96d\nWCERqJwPGWZsT4Yb+4VqoSgMN2it1mXXYSpsgdswwQKBgQDONpUpmK2qYMheCOwO\n0CQS3D4NiRY0UgBuaiUCE9Fn7NwCwFy7SN6lzYnP5l+v8YCYVoRZtwYLfiIMzIPx\nx9e4KY5EIwDuQUboqpmtCPK9sMqiZQUkPYCYC623ryhBAiTskh+Hcerhe2OSJhEW\nuxhO3UYJu2MQK5LGt4A1Y+pN4g==\n-----END PRIVATE KEY-----\n-----BEGIN CERTIFICATE-----\nMIIC8TCCAdmgAwIBAgIUaNrwbhs/I1ecqUYdzD2xuAVNdmowDQYJKoZIhvcNAQEL\nBQAwKjEPMA0GA1UECgwGUmF0aWZ5MRcwFQYDVQQDDA5SYXRpZnkgUm9vdCBDQTAe\nFw0yMzA2MjEwMTIyMzdaFw0yNDA2MjAwMTIyMzdaMBkxFzAVBgNVBAMMDnJhdGlm\neS5kZWZhdWx0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtskG1BUt\n4Fw2lbm53KbwZb1hnLmWdwRotZyznhhk/yrUDcq3uF6klwpk/E2IKfUKIo6doHSk\nXaEZXR68UtXygvA4wdg7xZ6kKpXy0gu+RxGE6CGtDHTyDDzITu+NBjo21ZSsyGpQ\nJeIKftUCHdwdygKf0CdJx8A29GBRpHGCmJadmt7tTzOnYjmbuPVLeqJo/Ex9qXcG\nZbxoxnxr5NCocFeKx+EbLo+k/KjdFB2PKnhgzxAaMMMP6eXPr8l5AlzkC83EmPvN\ntveuaBbamdlFkD+53TZeZlxt3GIdq93Iw/UpbQ/pvhbrztMT+UVEkm15sShfX8Xn\nL2st5A4n0V+66QIDAQABoyAwHjAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIH\ngDANBgkqhkiG9w0BAQsFAAOCAQEAGpOqozyfDSBjoTepsRroxxcZ4sq65gw45Bme\nm36BS6FG0WHIg3cMy6KIIBefTDSKrPkKNTtuF25AeGn9jM+26cnfDM78ZH0+Lnn7\n7hs0MA64WMPQaWs9/+89aM9NADV9vp2zdG4xMi6B7DruvKWyhJaNoRqK/qP6LdSQ\nw8M+21sAHvXgrRkQtJlVOzVhgwt36NOb1hzRlQiZB+nhv2Wbw7fbtAaADk3JAumf\nvM+YdPS1KfAFaYefm4yFd+9/C0KOkHico3LTbELO5hG0Mo/EYvtjM+Fljb42EweF\n3nAx1GSPe5Tn8p3h6RyJW5HIKozEKyfDuLS0ccB/nqT3oNjcTw==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIDRTCCAi2gAwIBAgIUcC33VfaMhOnsl7avNTRVQozoVtUwDQYJKoZIhvcNAQEL\nBQAwKjEPMA0GA1UECgwGUmF0aWZ5MRcwFQYDVQQDDA5SYXRpZnkgUm9vdCBDQTAe\nFw0yMzA2MjEwMTIyMzZaFw0yMzA2MjIwMTIyMzZaMCoxDzANBgNVBAoMBlJhdGlm\neTEXMBUGA1UEAwwOUmF0aWZ5IFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB\nDwAwggEKAoIBAQDDFhDnyPrVDZaeRu6Tbg1a/iTwus+IuX+h8aKhKS1yHz4EF/Lz\nxCy7lNSQ9srGMMVumWuNom/ydIphff6PejZM1jFKPU6OQR/0JX5epcVIjbKa562T\nDguUxJ+h5V3EIyM4RqOWQ2g/xZo86x5TzyNJXiVdHHRvmDvUNwPpMeDjr/EHVAni\n5YQObxkJRiiZ7XOa5zz3YztVm8sSZAwPWroY1HIfvtP+KHpiNDIKSymmuJkH4SEr\nJn++iqN8na18a9DFBPTTrLPe3CxATGrMfosCMZ6LP3iFLLc/FaSpwcnugWdewsUK\nYs+sUY7jFWR7x7/1nyFWyRrQviM4f4TY+K7NAgMBAAGjYzBhMB0GA1UdDgQWBBQH\nYePW7QPP2p1utr3r6gqzEkKs+DAfBgNVHSMEGDAWgBQHYePW7QPP2p1utr3r6gqz\nEkKs+DAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwICBDANBgkqhkiG9w0B\nAQsFAAOCAQEAjKp4vx3bFaKVhAbQeTsDjWJgmXLK2vLgt74MiUwSF6t0wehlfszE\nIcJagGJsvs5wKFf91bnwiqwPjmpse/thPNBAxh1uEoh81tOklv0BN790vsVpq3t+\ncnUvWPiCZdRlAiGGFtRmKk3Keq4sM6UdiUki9s+wnxypHVb4wIpVxu5R271Lnp5I\n+rb2EQ48iblt4XZPczf/5QJdTgbItjBNbuO8WVPOqUIhCiFuAQziLtNUq3p81dHO\nQ2BPgmaitCpIUYHVYighLauBGCH8xOFzj4a4KbOxKdxyJTd0La/vRCKaUtJX67Lc\nfQYVR9HXQZ0YlmwPcmIG5v7wBfcW34NUvA==\n-----END CERTIFICATE-----\n"
	contentType := "application/x-pem-file"
	id := "https://notarycerts.vault.azure.net/secrets/testCert6212/431ad135165741dcb95a46cf3e6686fb"
	test := kv.SecretBundle{
		Value:       &value,
		ID:          &id,
		ContentType: &contentType,
	}

	return test
}

func getSecretBundleText() kv.SecretBundle {

	value := "secretText"
	contentType := "text"
	id := "https://notarycerts.vault.azure.net/secrets/test/431ad135165741dcb95a46cf3e6686fb"
	test := kv.SecretBundle{
		Value:       &value,
		ID:          &id,
		ContentType: &contentType,
	}

	return test
}
