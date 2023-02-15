/* http_get_bearssl - HTTPS version of the http_get example, using BearSSL.
 *
 * Retrieves a JSON response from the howsmyssl.com API via HTTPS over TLS v1.2.
 *
 * Validates the server's certificate using a hardcoded public key.
 *
 * Adapted from the client_basic sample in BearSSL.
 *
 * Original Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>, MIT License.
 * Additions Copyright (C) 2016 Stefan Schake, MIT License.
 */
#include "espressif/esp_common.h"
#include "esp/uart.h"
#include "esp/hwrand.h"

#include <unistd.h>
#include <string.h>

#include "FreeRTOS.h"
#include "task.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include "lwip/api.h"

#include "wifi.h"
#include "login_params.h"

#include "bearssl.h"
#include "http-parser/http_parser.h"
#include "sysparam.h"

#define CLOCK_SECONDS_PER_MINUTE (60UL)
#define CLOCK_MINUTES_PER_HOUR (60UL)
#define CLOCK_HOURS_PER_DAY (24UL)
#define CLOCK_SECONDS_PER_HOUR (CLOCK_MINUTES_PER_HOUR*CLOCK_SECONDS_PER_MINUTE)
#define CLOCK_SECONDS_PER_DAY (CLOCK_HOURS_PER_DAY*CLOCK_SECONDS_PER_HOUR)

#define WEB_SERVER "www.mytotalconnectcomfort.com"
#define WEB_PORT "443"
#define WEB_URL "https://mytotalconnectcomfort.com/portal/"

//#define GET_REQUEST "GET "WEB_URL" HTTP/1.1\nHost: "WEB_SERVER"\n\n"

#define GET_REQUEST \
"GET /portal/ HTTP/1.1\n" \
"Content-Type:application/x-www-form-urlencoded\n" \
"Accept:text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\n" \
"Accept-Encoding:sdch\n" \
"Host:mytotalconnectcomfort.com\n" \
"DNT:1\n" \
"Origin:https://mytotalconnectcomfort.com/portal\n" \
"User-Agent:Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.95 Safari/537.36\n\n"


#define LOGIN_REQUEST_FORMAT \
"POST /portal/ HTTP/1.1\n" \
"Content-Length: %d\n" \
"Origin: https://mytotalconnectcomfort.com/portal/\n" \
"DNT: 1\n" \
"Host: mytotalconnectcomfort.com\n" \
"Cookie: \n" \
"Accept-Encoding: sdch\n" \
"Content-Type: application/x-www-form-urlencoded\n" \
"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\n" \
"User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.95 Safari/537.36\n\n" \
"%s\n\n"

#define LOGOUT_REQUEST_FORMAT \
"GET https://mytotalconnectcomfort.com/portal/Account/LogOff HTTP/1.1\n" \
"Accept-Language: en-US,en,q=0.8\n" \
"Accept-Encoding: plain\n" \
"DNT: 1\n" \
"Connection: keep-alive\n" \
"X-Requested-With: XMLHttpRequest\n" \
"Accept: */*\n" \
"User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.95 Safari/537.36\n" \
"Host: mytotalconnectcomfort.com\n" \
"Cache-Control: max-age=0\n" \
"Referer: https://mytotalconnectcomfort.com/portal/\n" \
"Cookie: "

#define DATA_REQUEST_FORMAT \
"GET /portal/Device/CheckDataSession/"DEVICE_ID"?_=1676182744000 HTTP/1.1\n" \
"Accept:*/*\n" \
"DNT:1\n" \
"Accept-Encoding:plain\n" \
"Cache-Control:max-age=0\n" \
"Accept-Language:en-US,en,q=0.8\n" \
"Connection:keep-alive\n" \
"Host:mytotalconnectcomfort.com\n" \
"Referer:https://mytotalconnectcomfort.com/portal/\n" \
"X-Requested-With:XMLHttpRequest\n" \
"User-Agent:Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.95 Safari/537.36\n" \
"Cache-Control: max-age=0\n" \
"Referer: https://mytotalconnectcomfort.com/portal/\n" \
"Cookie: "

#define DATA_SEND_REQUEST_FORMAT \
"POST /portal/Device/SubmitControlScreenChanges HTTP/1.1\n" \
"Accept-Encoding: gzip,deflate,sdch\n" \
"Accept: application/json; q=0.01\n" \
"DNT:1\n" \
"Cache-Control:max-age=0\n" \
"Accept-Language:en-US,en,q=0.8\n" \
"Connection:keep-alive\n" \
"Host:mytotalconnectcomfort.com\n" \
"Referer:/TotalConnectComfort/Device/CheckDataSession/"DEVICE_ID"\n" \
"X-Requested-With:XMLHttpRequest\n" \
"User-Agent:Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.95 Safari/537.36\n" \
"Cache-Control: max-age=0\n" \
"Content-Type: application/json; charset=UTF-8\n" \
"Cookie: "

#define LOGIN_PARAMS "timeOffset=240&UserName="EMAIL"&Password="PASSWORD"&RememberMe=true"

#define MAX_ELEMENT_SIZE 1000
#define MAX_HEADERS 100

typedef enum state_t_ {
    INITIAL_CONNECT,
    LOGIN,
    DATA,
    DATA_SEND,
    LOGOUT
} state_t;

http_parser_settings parser_settings;
http_parser parser;

bool next_is_cookie = false;
bool message_complete = false;
char post_request[4096];
char buf[512];
state_t state;
size_t len;
uint32_t base_addr, num_sectors;
bool use_saved_cookies = false;
sysparam_status_t sysparam_status;
char input_buf[200] = "{\"DeviceID\":7914718,\"SystemSwitch\":null,\"HeatSetpoint\":69,\"CoolSetpoint\":null,\"HeatNextPeriod\":null,\"CoolNextPeriod\":null,\"StatusHeat\":null,\"StatusCool\":null,\"FanMode\":null}";

/*
 * Low-level data read callback for the simplified SSL I/O API.
 */
static int
sock_read(void *ctx, unsigned char *buf, size_t len)
{
    for (;;) {
        static ssize_t rlen;

        rlen = read(*(int *)ctx, buf, len);
        if (rlen <= 0) {
            if (rlen < 0 && errno == EINTR) {
                    continue;
            }
            return -1;
        }
        return (int)rlen;
    }
}

/*
 * Low-level data write callback for the simplified SSL I/O API.
 */
static int
sock_write(void *ctx, const unsigned char *buf, size_t len)
{
    for (;;) {
        static ssize_t wlen;

        wlen = write(*(int *)ctx, buf, len);
        if (wlen <= 0) {
            if (wlen < 0 && errno == EINTR) {
                    continue;
            }
            return -1;
        }
        return (int)wlen;
    }
}

/*
 * The hardcoded trust anchors. These are the two DN + public key that
 * correspond to the self-signed certificates cert-root-rsa.pem and
 * cert-root-ec.pem.
 *
 * C code for hardcoded trust anchors can be generated with the "brssl"
 * command-line tool (with the "ta" command). To build that tool run:
 *
 * $ cd /path/to/esp-open-rtos/extras/bearssl/BearSSL
 * $ make build/brssl
 *
 * Below is the imported "Let's Encrypt" root certificate, as howsmyssl
 * is depending on it:
 *
 * https://letsencrypt.org/certs/letsencryptauthorityx3.pem
 *
 * The generate the trust anchor code below, run:
 *
 * $ /path/to/esp-open-rtos/extras/bearssl/BearSSL/build/brssl \
 *   ta letsencryptauthorityx3.pem
 *
 * To get the server certificate for a given https host:
 *
 * $ openssl s_client -showcerts -servername www.howsmyssl.com \
 *   -connect www.howsmyssl.com:443 < /dev/null | \
 *   openssl x509 -outform pem > server.pem
 */

static const unsigned char TA0_DN[] = {
        0x30, 0x81, 0x81, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06,
        0x13, 0x02, 0x55, 0x53, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04,
        0x08, 0x13, 0x09, 0x4D, 0x69, 0x6E, 0x6E, 0x65, 0x73, 0x6F, 0x74, 0x61,
        0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x0D, 0x47,
        0x6F, 0x6C, 0x64, 0x65, 0x6E, 0x20, 0x56, 0x61, 0x6C, 0x6C, 0x65, 0x79,
        0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x19, 0x52,
        0x65, 0x73, 0x69, 0x64, 0x65, 0x6F, 0x20, 0x54, 0x65, 0x63, 0x68, 0x6E,
        0x6F, 0x6C, 0x6F, 0x67, 0x69, 0x65, 0x73, 0x20, 0x49, 0x6E, 0x63, 0x2E,
        0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x19, 0x6D,
        0x79, 0x74, 0x6F, 0x74, 0x61, 0x6C, 0x63, 0x6F, 0x6E, 0x6E, 0x65, 0x63,
        0x74, 0x63, 0x6F, 0x6D, 0x66, 0x6F, 0x72, 0x74, 0x2E, 0x63, 0x6F, 0x6D
};

static const unsigned char TA0_RSA_N[] = {
        0xB3, 0xDD, 0x71, 0x83, 0x73, 0x79, 0x3F, 0x08, 0xFF, 0x03, 0x41, 0x98,
        0x55, 0x8F, 0xF7, 0xED, 0xC1, 0x49, 0x76, 0xD9, 0xA8, 0xED, 0x8A, 0x7D,
        0x24, 0x42, 0xCB, 0xCD, 0x24, 0x32, 0xD6, 0x72, 0x70, 0xAB, 0x97, 0xB2,
        0x96, 0x83, 0x69, 0xF7, 0x13, 0x87, 0x3D, 0x36, 0xEE, 0xFD, 0xE2, 0x81,
        0x86, 0x4F, 0x45, 0x57, 0xB7, 0xB0, 0xE9, 0x0C, 0xA5, 0x91, 0x5A, 0xC2,
        0xED, 0xCD, 0x96, 0xB6, 0x4F, 0x21, 0x9A, 0xBF, 0x2B, 0x7F, 0xD6, 0xBA,
        0x3D, 0xB9, 0xD0, 0xAD, 0xD8, 0x47, 0xC9, 0xFC, 0x9A, 0x08, 0x6F, 0xCE,
        0x6B, 0x35, 0xD2, 0x2C, 0x81, 0xF9, 0xCD, 0x84, 0x19, 0xAE, 0xB1, 0x78,
        0x93, 0xAC, 0xB2, 0x98, 0xE6, 0xC9, 0xE3, 0x65, 0xEC, 0x7E, 0x0E, 0x4B,
        0x92, 0x75, 0xCA, 0xCC, 0xB6, 0xB2, 0x4C, 0x0D, 0x55, 0x77, 0x29, 0x51,
        0x5F, 0x6C, 0x54, 0xD7, 0x09, 0x12, 0x05, 0x33, 0x60, 0x1A, 0x60, 0xA1,
        0xDB, 0x0A, 0x8A, 0x21, 0x33, 0xC1, 0xC1, 0xF1, 0x61, 0x0C, 0x11, 0x4C,
        0xC3, 0x92, 0x14, 0x52, 0xCD, 0x50, 0x27, 0x56, 0x87, 0x55, 0x2D, 0x85,
        0x31, 0xB8, 0x93, 0xCD, 0x91, 0xAF, 0x38, 0x6B, 0x08, 0x54, 0x53, 0xF9,
        0xEA, 0x0A, 0x76, 0x7E, 0x4D, 0x1D, 0x8D, 0x22, 0x1F, 0x7E, 0xB9, 0xBC,
        0x18, 0x5A, 0x63, 0xED, 0xB4, 0x2C, 0x8F, 0x14, 0x60, 0xDA, 0xE8, 0x55,
        0x21, 0x30, 0xAF, 0xC8, 0x4A, 0x63, 0xA9, 0x48, 0x00, 0x98, 0xC0, 0x19,
        0x34, 0xD1, 0xDD, 0xAD, 0x84, 0x52, 0x47, 0x93, 0xFE, 0x16, 0x5C, 0x34,
        0xDA, 0xBD, 0x08, 0x0F, 0x30, 0x2B, 0x1A, 0xB2, 0x15, 0xBA, 0xCC, 0x01,
        0x0A, 0xFB, 0x3F, 0x06, 0x59, 0xA4, 0xA0, 0x3C, 0x03, 0x00, 0x2F, 0x7F,
        0x22, 0xA9, 0x4F, 0x8A, 0xB1, 0x63, 0xCD, 0x1F, 0xDE, 0xED, 0x5D, 0xE8,
        0xE2, 0x69, 0x36, 0x37
};

static const unsigned char TA0_RSA_E[] = {
        0x01, 0x00, 0x01
};

static const br_x509_trust_anchor TAs[1] = {
        {
                { (unsigned char *)TA0_DN, sizeof TA0_DN },
                0,
                {
                        BR_KEYTYPE_RSA,
                        { .rsa = {
                                (unsigned char *)TA0_RSA_N, sizeof TA0_RSA_N,
                                (unsigned char *)TA0_RSA_E, sizeof TA0_RSA_E,
                        } }
                }
        }
};

#define TAs_NUM   1


/*
 * Buffer to store a record + BearSSL state
 * We use MONO mode to save 16k of RAM.
 * This could be even smaller by using max_fragment_len, but
 * the howsmyssl.com server doesn't seem to support it.
 */
static unsigned char bearssl_buffer[BR_SSL_BUFSIZE_MONO];

static br_ssl_client_context sc;
static br_x509_minimal_context xc;
static br_sslio_context ioc;

//void strncopy_(char *dest, char *src, size_t len) {
//   while (*src) {
//      *(dst++) = *(src++);
//   }
//}

void http_get_task(void *pvParameters)
{
    static int successes = 0, failures = 0;
    static int provisional_time = 0;

        /*
         * Wait until we can resolve the DNS for the server, as an indication
         * our network is probably working...
         */
        static const struct addrinfo hints = {
            .ai_family = AF_INET,
            .ai_socktype = SOCK_STREAM,
        };
        static struct addrinfo *res = NULL;
        static int dns_err = 0;
        do {
            if (res)
                freeaddrinfo(res);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            dns_err = getaddrinfo(WEB_SERVER, WEB_PORT, &hints, &res);
        } while(dns_err != 0 || res == NULL);

        static int fd;
        fd = socket(res->ai_family, res->ai_socktype, 0);
        if (fd < 0) {
            freeaddrinfo(res);
            printf("socket failed\n");
            failures++;
            for (;;) {}
        }

        printf("Initializing BearSSL... ");
        br_ssl_client_init_full(&sc, &xc, TAs, TAs_NUM);

        /*
         * Set the I/O buffer to the provided array. We allocated a
         * buffer large enough for full-duplex behaviour with all
         * allowed sizes of SSL records, hence we set the last argument
         * to 1 (which means "split the buffer into separate input and
         * output areas").
         */
        br_ssl_engine_set_buffer(&sc.eng, bearssl_buffer, sizeof bearssl_buffer, 0);

        /*
         * Inject some entropy from the ESP hardware RNG
         * This is necessary because we don't support any of the BearSSL methods
         */
        for (int i = 0; i < 10; i++) {
            static int rand;
            rand = hwrand();
            br_ssl_engine_inject_entropy(&sc.eng, &rand, 4);
        }

        /*
         * Reset the client context, for a new handshake. We provide the
         * target host name: it will be used for the SNI extension. The
         * last parameter is 0: we are not trying to resume a session.
         */
        br_ssl_client_reset(&sc, WEB_SERVER, 0);

        /*
         * Initialise the simplified I/O wrapper context, to use our
         * SSL client context, and the two callbacks for socket I/O.
         */
        br_sslio_init(&ioc, &sc.eng, sock_read, &fd, sock_write, &fd);
        printf("done.\r\n");

        /* FIXME: set date & time using epoch time precompiler flag for now */
        provisional_time = CONFIG_EPOCH_TIME + (xTaskGetTickCount()/configTICK_RATE_HZ);
        xc.days = (provisional_time / CLOCK_SECONDS_PER_DAY) + 719528;
        xc.seconds = provisional_time % CLOCK_SECONDS_PER_DAY;
        printf("Time: %02i:%02i\r\n",
            (int)(xc.seconds / CLOCK_SECONDS_PER_HOUR),
            (int)((xc.seconds % CLOCK_SECONDS_PER_HOUR)/CLOCK_SECONDS_PER_MINUTE)
        );

        if (connect(fd, res->ai_addr, res->ai_addrlen) != 0)
        {
            close(fd);
            freeaddrinfo(res);
            printf("connect failed\n");
            failures++;
            for (;;) {}
        }
        printf("Connected\r\n");

    while (1) {


        /*
         * Note that while the context has, at that point, already
         * assembled the ClientHello to send, nothing happened on the
         * network yet. Real I/O will occur only with the next call.
         *
         * We write our simple HTTP request. We test the call
         * for an error (-1), but this is not strictly necessary, since
         * the error state "sticks": if the context fails for any reason
         * (e.g. bad server certificate), then it will remain in failed
         * state and all subsequent calls will return -1 as well.
         */

			static int result;

			message_complete = false;
         //http_parser_init(&parser, HTTP_RESPONSE);
            memset(post_request, 0, sizeof(post_request));

			switch (state) {
				case INITIAL_CONNECT:
                    printf("INITIAL_CONNECT\r\n");
                    printf("----------------POST REQUEST----------------------\r\n");
                    printf("%s\r\n", GET_REQUEST);
                    printf("----------------END REQUEST----------------------\r\n");
                    result = br_sslio_write_all(&ioc, GET_REQUEST, strlen(GET_REQUEST));
			    break;
                case LOGIN:
                    printf("LOGIN\r\n");
                    snprintf(post_request, sizeof(post_request), LOGIN_REQUEST_FORMAT, strlen(LOGIN_PARAMS), LOGIN_PARAMS);
                    printf("----------------POST REQUEST----------------------\r\n");
                    printf("%s\r\n", post_request);
                    printf("----------------END REQUEST----------------------\r\n");
                    result = br_sslio_write_all(&ioc, post_request, strlen(post_request));
                break;
                case DATA:
                    printf("DATA\r\n");
                    snprintf(post_request, sizeof(post_request), DATA_REQUEST_FORMAT);
                    sysparam_get_data_static("cookies", (uint8_t *) post_request + strlen(post_request), sizeof(post_request) - strlen(post_request), &len, NULL);
                    strncat(post_request, "\n\n", sizeof(post_request) - strlen(post_request));
                    printf("request size: %d\r\n", strlen(post_request));
                    printf("----------------GET REQUEST----------------------\r\n");
                    printf("%s\r\n", post_request);
                    printf("----------------GET REQUEST----------------------\r\n");
                    result = br_sslio_write_all(&ioc, post_request, strlen(post_request));
                break;
                case DATA_SEND:
                    printf("SEND_DATA\r\n");
                    snprintf(post_request, sizeof(post_request), DATA_SEND_REQUEST_FORMAT);
                    sysparam_get_data_static("cookies", (uint8_t *) post_request + strlen(post_request), sizeof(post_request) - strlen(post_request), &len, NULL);
                    strncat(post_request, "\n", sizeof(post_request) - strlen(post_request));
                    snprintf(post_request + strlen(post_request), sizeof(post_request) - strlen(post_request), "Content-Length: %d", strlen(input_buf));
                    strncat(post_request, "\n", sizeof(post_request) - strlen(post_request));
                    strncat(post_request, "\n", sizeof(post_request) - strlen(post_request));
                    strncat(post_request, input_buf, sizeof(post_request) - strlen(post_request));
                    printf("request size: %d\r\n", strlen(post_request));
                    printf("----------------POST REQUEST----------------------\r\n");
                    printf("%s\r\n", post_request);
                    printf("----------------POST REQUEST----------------------\r\n");
                    result = br_sslio_write_all(&ioc, post_request, strlen(post_request));
                break;    
                case LOGOUT:
                    printf("LOGOUT\r\n");
                    snprintf(post_request, sizeof(post_request), LOGOUT_REQUEST_FORMAT);
                    sysparam_get_data_static("cookies", (uint8_t *) post_request + strlen(post_request), sizeof(post_request) - strlen(post_request), &len, NULL);
                    strncat(post_request, "\n\n", sizeof(post_request));
                    printf("----------------GET REQUEST----------------------\r\n");
                    printf("%s\r\n", post_request);
                    printf("----------------END REQUEST----------------------\r\n");
                    result = br_sslio_write_all(&ioc, post_request, strlen(post_request));
                break;
            }

            if (result != BR_ERR_OK) {
                close(fd);
                freeaddrinfo(res);
                printf("br_sslio_write_all failed: %d\r\n", br_ssl_engine_last_error(&sc.eng));
                failures++;
                continue;
            }

        /*
         * SSL is a buffered protocol: we make sure that all our request
         * bytes are sent onto the wire.
         */
        br_sslio_flush(&ioc);


         switch (state) {
            case INITIAL_CONNECT:
               break;
            case LOGIN:
               //snprintf(post_request, sizeof(post_request), DATA_REQUEST_FORMAT);
               memset(post_request, 0, sizeof(post_request));
               break;
            case DATA:
               //snprintf(post_request, sizeof(post_request), LOGOUT_REQUEST_FORMAT);
               break;
            case LOGOUT:
               break;
            default:
                break;
         }

        /*
         * Read and print the server response
         */
        for (;;)
        {
            static int rlen;

            bzero(buf, sizeof(buf));
            // Leave the final byte for zero termination
            if (!message_complete)
               rlen = br_sslio_read(&ioc, buf, sizeof(buf) - 1);
            else {
               break;
			}


            if (rlen < 0) {
                printf("Read 0\n");
                break;
            }
            if (rlen > 0) {
               printf("%s", buf);
               http_parser_execute(&parser, &parser_settings, buf, rlen);
            }
        }

        /*
         * If reading the response failed for any reason, we detect it here
         */
        if (br_ssl_engine_last_error(&sc.eng) != BR_ERR_OK) {
            close(fd);
            freeaddrinfo(res);
            printf("failure, error = %d\r\n", br_ssl_engine_last_error(&sc.eng));
            failures++;
            continue;
        }

        printf("\r\n\r\nfree heap pre  = %u\r\n", xPortGetFreeHeapSize());

        /*
         * Close the connection and start over after a delay
         */
        //close(fd);
        //freeaddrinfo(res);

        printf("free heap post = %u\r\n", xPortGetFreeHeapSize());

        successes++;
        printf("successes = %d failures = %d\r\n", successes, failures);

        
        switch (state) {
            case INITIAL_CONNECT:
                state = LOGIN;
                break;
            case LOGIN:
                if (strlen(post_request) >= 1000) {
                    static char *string_to_skip;
                    string_to_skip = strstr(post_request, ".ASPXAUTH_TRUEHOME=;");
                    strcpy(post_request, post_request + strlen(".ASPXAUTH_TRUEHOME=;"));
                    printf("about to save this to \"cookies\":\r\n");
                    printf("%s\r\n", post_request);
                    printf("-----------------------------------------------------\r\n");
                    sysparam_set_string("cookies", post_request);
                    state = DATA;
                } else {
                    state = LOGIN;
                }
                break;
            case DATA:
                state = DATA_SEND;
                break;
            case LOGOUT:
                state = LOGIN;
                break;
            default:
                break;
        }

        printf("What now? (g = get data, s = set data) >\r\n");

        static char option;
        fgets(input_buf, sizeof(input_buf), stdin); printf("\r\n");
        sscanf(input_buf, "%c", &option);

        switch (option) {
            case ('i'):
               state = LOGIN;
               break;
            case('o'):
               state = LOGOUT;
               break;
            case ('g'):
                state = DATA;
                break;
            case ('s'):
                printf("okay what data?\r\n");
                fgets(input_buf, sizeof(input_buf), stdin);
                *strchr(input_buf, '\n') = 0;
                *strchr(input_buf, '\r') = 0;

                state = DATA_SEND;
                break;
        }


        //printf("Press any key to refresh\r\n");
        //getchar();
        for(int countdown = 1; countdown >= 0; countdown--) {
            printf("%d...\n", countdown);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
        }
        //printf("Starting again!\r\n\r\n");
    }
}

void strnlwr(char *p, size_t len) {

   for (char *ptr = p; ptr < p+len; ptr++) {
      if (*ptr >= 'A' && *ptr <= 'Z') {
         *ptr += 32;
      }
   }

}

int header_value_cb (http_parser *parser, const char *p, size_t len) {
    //printf("enter vale_cb\r\n");
	if (next_is_cookie) {
		//strncat(cookies, p, len);
		//printf("%.*s\r\n", len, p);
		static char *semicolon;
        semicolon = strchr(p, ';');
		//if (*(semicolon - 1) != '=') 
		if (semicolon) {
			strncat(post_request, p, semicolon - p + 1);
			next_is_cookie = false;
		} else {
			strncat(post_request, p, len);
		}

   }
    //printf("exit vale_cb\r\n");

	return 0;
}

int header_field_cb (http_parser *parser, char *p, size_t len) {


    // Only care about saving cookies when we're trying to log in
    if (state == LOGIN) {
        //printf("enter field cb\r\n");
        strnlwr(p, len);

        if (strncmp(p, "set-cookie", len) == 0) {
            printf("Saw set-cookie\n");
            next_is_cookie = true;
        }
        //printf("exit field cb\r\n");
    }

	return 0;
}

int message_complete_cb (http_parser *parser) {
   	message_complete = true;
	//br_sslio_close(&ioc);
	return 0;
}

void user_init(void)
{
    uart_set_baud(0, 921600);
    printf("SDK version:%s\n", sdk_system_get_sdk_version());

    struct sdk_station_config config = {
        .ssid = WIFI_SSID,
        .password = WIFI_PASSWORD,
    };

    /* required to call wifi_set_opmode before station_set_config */
    sdk_wifi_set_opmode(STATION_MODE);
    sdk_wifi_station_set_config(&config);


    sysparam_status = sysparam_get_info(&base_addr, &num_sectors);
    if (SYSPARAM_OK != sysparam_status) {
        printf("sysparam sysparam_status %d, reinitializing\r\n", sysparam_status);
        num_sectors = DEFAULT_SYSPARAM_SECTORS;
        base_addr = sdk_flashchip.chip_size - (5 + num_sectors) * sdk_flashchip.sector_size;
        sysparam_status = sysparam_create_area(base_addr, num_sectors, true);
        if (sysparam_status == SYSPARAM_OK) {
            // We need to re-init after wiping out the region we've been
            // using.
            sysparam_status = sysparam_init(base_addr, 0);
        }
        if (SYSPARAM_OK != sysparam_status) {
            printf("sysparam init problem\r\n");
        }

    }

    if (SYSPARAM_OK == sysparam_status) {
        sysparam_status = sysparam_get_data_static("cookies", (uint8_t *) post_request, sizeof(post_request), &len, NULL);
        if (SYSPARAM_OK == sysparam_status) {
            use_saved_cookies = true;
        } else {
            printf("Cookies not found, error %d\r\n", sysparam_status);
        }
    }

   http_parser_init(&parser, HTTP_RESPONSE);

	parser_settings.on_header_field = header_field_cb;
	parser_settings.on_header_value = header_value_cb;
   parser_settings.on_message_complete = message_complete_cb;


    if (use_saved_cookies) {
	    state = DATA;
    } else {
        state = LOGIN;
    }


    xTaskCreate(&http_get_task, "get_task", 2048, NULL, 2, NULL);
}
