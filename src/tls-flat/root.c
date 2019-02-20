/**
 *  Copyright 2018, raprepo.
 *  Created by raprepo on 2018/8/23.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <stdlib.h>

const unsigned char root_crt[] = {
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIIDijCCAnKgAwIBAgIRAPqRJQ3HafcNMqwuqh6lcQUwDQYJKoZIhvcNAQELBQAw\r\n"
    "TTEgMB4GA1UEAxMXT3BlblNpZ24gR2xvYmFsIFJvb3QgRzMxHDAaBgNVBAoTE09w\r\n"
    "ZW5TaWduIENlcnR1bSBMTEMxCzAJBgNVBAYTAlVLMB4XDTA5MDgwMTA3MDAwMVoX\r\n"
    "DTM5MDgwMTA2NTk1OVowTTEgMB4GA1UEAxMXT3BlblNpZ24gR2xvYmFsIFJvb3Qg\r\n"
    "RzMxHDAaBgNVBAoTE09wZW5TaWduIENlcnR1bSBMTEMxCzAJBgNVBAYTAlVLMIIB\r\n"
    "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2ABqRYk+89mIQc2KuGloi+gH\r\n"
    "ne4wM4o39i1MKcI0i5DsVKPzERbSdVfzNZov5LeDuQ/ZKXMlBHtPS4dtcxCUseCS\r\n"
    "L68y9Qi7LPD4oMzo3FFbW9uMR2Wga3wej7mm+VGLBX9SWAyKDsoWuZt6YYWbH+hc\r\n"
    "62NqvAM+ShXWdWhMkBYDwfosRAcpP/Y3VThOjKKByb8ajWiLo54Su2scIKpadZvP\r\n"
    "OLT8BHcwab+XkKd8PnEyPvUG1XWHikA+j4wSXD6VMSXOeF3g0vxZcSVKKOdhZLcW\r\n"
    "OUvlMpkuB0B51Y6okWenyCC2V8VzZbVLBGzNPWEGlc27CfoAVLhToUNS5HxTtQID\r\n"
    "AQABo2UwYzAdBgNVHQ4EFgQU3aJUjTpbuMH/Qf5rfqHmRavLM3UwDwYDVR0TBAgw\r\n"
    "BgEB/wIBADAxBgNVHSUEKjAoBggrBgEFBQcDBAYIKwYBBQUHAwMGCCsGAQUFBwMC\r\n"
    "BggrBgEFBQcDATANBgkqhkiG9w0BAQsFAAOCAQEAwTcIBj2PGC2Nxw6RAjSCnzWP\r\n"
    "Jlj1KI/ejWsFLjkcN1jZGT8F2QxvJiMksFCkmYp6IEi50Nhv+gwCIwWm8EtKcFoF\r\n"
    "HnOMU5+2GTFFhAjch0FY+X0ZLo5YIuiod7Yhp9GQunPplMoRoJWn6xVKrS1W/QtT\r\n"
    "E3uO3jsxWOXcyutuEK3wv5Ek2daReWNP3Pjj6lSzUNqJ25VTmxIETRttk07WKXh4\r\n"
    "fITqBKYMTfNt8V1Go/0Q1aMoYivJET+ir1tJFjoZWI8p0lgPGyQWBT25vTpByCh4\r\n"
    "FJ6T2q7+N1PYT4nyaVBHY1CoFY4x1yq+gJMHK86hj2jTg/x2v5RgmzeCOLZZwQ==\r\n"
    "-----END CERTIFICATE-----\r\n"
};
const size_t root_crt_len = sizeof(root_crt);

const unsigned char root_key[] = {
    "-----BEGIN RSA PRIVATE KEY-----\r\n"
    "MIIEowIBAAKCAQEA2ABqRYk+89mIQc2KuGloi+gHne4wM4o39i1MKcI0i5DsVKPz\r\n"
    "ERbSdVfzNZov5LeDuQ/ZKXMlBHtPS4dtcxCUseCSL68y9Qi7LPD4oMzo3FFbW9uM\r\n"
    "R2Wga3wej7mm+VGLBX9SWAyKDsoWuZt6YYWbH+hc62NqvAM+ShXWdWhMkBYDwfos\r\n"
    "RAcpP/Y3VThOjKKByb8ajWiLo54Su2scIKpadZvPOLT8BHcwab+XkKd8PnEyPvUG\r\n"
    "1XWHikA+j4wSXD6VMSXOeF3g0vxZcSVKKOdhZLcWOUvlMpkuB0B51Y6okWenyCC2\r\n"
    "V8VzZbVLBGzNPWEGlc27CfoAVLhToUNS5HxTtQIDAQABAoIBAGQrDR1iIEeFQaMC\r\n"
    "ZqpOd6Up3R5oLwI3vuvy5bcX0LZIZtB5l2b9Zmv0dV0OO9edIwDXUKXgN/J0HLmx\r\n"
    "/Be4QLycoC5s2Py5J9QXi7VGUVaag/t9PPh/MH2n+aQ9PCmynv3VpaIfboadQRyh\r\n"
    "9Yb0JpQNdcnTONQnzOMebW3VCGxobtlGNKAwUacduzsJcEHEaCjMPE/38D45UkzE\r\n"
    "sDuGtkzm/eIMBEyQFYFQpA4oZS+1mONYP0N9dJzgllSa3hv61mKhHX1kucXIoX90\r\n"
    "ggkczrK8TFDIwcLlVxy1CMpsj+qIfXXZqgDba90OKD/9wOcGZFVG263n/qXXFZvo\r\n"
    "cL+KYKECgYEA9V72KxP+FWF2SILK0FW7KrL3dYrkRUKY0guAOqBYi/tuEKwGVlsM\r\n"
    "vLGJXFnIfhMIGqCaND/bBy4/PdeU8BqcT8TuabLhKGF4kGLIq2pCmaPxwCiTIYpE\r\n"
    "FAiMutxOSIxpkKqIfKiU2x3QfVjEutJ2bQcmHAc4aTjSFUC9QeooVXMCgYEA4VvD\r\n"
    "Q6TXZgSCvkwnuHn7Iq+kW8sFp5C3fBIKTt3+xXwFW0furYqEG9YUW7RfvVfcp4wm\r\n"
    "pMw2xN8X9Ffc1JHh/6HK5qMaAb0Iz8tDEXS7FjHAj0z9V4oVZ5tFyvkSVKOMei/u\r\n"
    "WJflWiWTwrPCetNwMsMwaC+JfJO7J6SIYreoKDcCgYEAxWQ5gPo6YxTexQKDCgqN\r\n"
    "4ZHLxUGQ1a73pbIe3Ar2cNY5+yuIhZwFqR7hs+t+gP3qfRFKPFJKb4Ji2es+I9Ik\r\n"
    "gX+ZlGqU+5k+FlmBuXRoU5Ux/DYn9sl2bu9Z11E3oOFkYz7tQeuUpJldihkJWonJ\r\n"
    "P3iKze15Ehzl1LcaCZbID8UCgYBhrZpnGW3bZB0fSnb0+LongKXmu4rJ5GoDNvaM\r\n"
    "1J/3DRhtRjJnueAlCJduYDIXKZwUayTczT73+hKx79thr5GbcY82hH9jPYIyPtHl\r\n"
    "IQluR0ZFVoOAi/NXIvAPWAHf+buLwna2o6/fcOYowC2Ne1PoTL4Qino3Kvk155TN\r\n"
    "5PjX5QKBgH4JvxANNohHeB93xSNMlE0zv4NBl2P9LthOCVcbeAFhTc5esjLDiBDU\r\n"
    "oQSYMcPPN0sAS+s+WRThCj2pRuVEPEL3Zy8Nld5a2By7dWRnLQkbCncCHJ24baaU\r\n"
    "BXMIpI4fMbHM+ByiZX5+dlDplftVf3+zzprKDBGqOCCMBmj6dT64\r\n"
    "-----END RSA PRIVATE KEY-----\r\n"

};
const size_t root_key_len = sizeof(root_key);
