/* Includes ---------------------------------------------------------------- */
#include <stdio.h>
#include "pico/stdlib.h"
#include "ei_run_classifier.h"
#include "hardware/gpio.h"
#include "hardware/adc.h"
#include "pico/cyw43_arch.h"

#include "hardware/structs/rosc.h"

#include <string.h>
#include <time.h>

#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/dns.h"

#include "lwip/altcp_tcp.h"
#include "lwip/altcp_tls.h"
#include "lwip/apps/mqtt.h"

#include "lwip/apps/mqtt_priv.h"

#include "tusb.h"
#include <string>

#define DEBUG_printf printf

#define MQTT_TLS 0 // needs to be 1 for AWS IoT
//#define CRYPTO_AWS_IOT
#define CRYPTO_MOSQUITTO_LOCAL
#include "/home/fd/example-standalone-inferencing-pico/source/crypto_consts.h"


#if MQTT_TLS
#ifdef CRYPTO_CERT
const char *cert = CRYPTO_CERT;
#endif
#ifdef CRYPTO_CA
const char *ca = CRYPTO_CA;
#endif
#ifdef CRYPTO_KEY
const char *key = CRYPTO_KEY;
#endif
#endif

#define FREQUENCY_HZ        50
#define INTERVAL_MS         (1000 / (FREQUENCY_HZ + 1))

/* Constant defines -------------------------------------------------------- */
#define CONVERT_G_TO_MS2    9.80665f
#define G0 1.65f
#define NSAMP 10
 
char ssid[] = "";
char pass[] = "";


/* Private variables ------------------------------------------------------- */
static bool debug_nn = false; // Set this to true to see e.g. features generated from the raw signal
 
const float conversion_factor = 3.3f / (1 << 12);

float readAxisAccelation (int adc_n) {
    adc_select_input(adc_n);
    unsigned int axis_raw = 0;
    for (int i=0;i<NSAMP;i++){
        axis_raw = axis_raw + adc_read();
        sleep_ms(1);
    }
    axis_raw = axis_raw/NSAMP;
    float axis_g = (axis_raw*conversion_factor)-G0;
    return axis_g;
}

typedef struct MQTT_CLIENT_T_ {
    ip_addr_t remote_addr;
    mqtt_client_t *mqtt_client;
    u8_t receiving;
    u32_t received;
    u32_t counter;
    u32_t reconnect;
} MQTT_CLIENT_T;
 
err_t mqtt_test_connect(MQTT_CLIENT_T *state);

/* cribbed from https://github.com/peterharperuk/pico-examples/tree/add_mbedtls_example */
/* Function to feed mbedtls entropy. May be better to move it to pico-sdk */
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen) {
    /* Code borrowed from pico_lwip_random_byte(), which is static, so we cannot call it directly */
    static uint8_t byte;

    for(int p=0; p<len; p++) {
        for(int i=0;i<32;i++) {
            // picked a fairly arbitrary polynomial of 0x35u - this doesn't have to be crazily uniform.
            byte = ((byte << 1) | rosc_hw->randombit) ^ (byte & 0x80u ? 0x35u : 0);
            // delay a little because the random bit is a little slow
            busy_wait_at_least_cycles(30);
        }
        output[p] = byte;
    }

    *olen = len;
    return 0;
}

// Perform initialisation
static MQTT_CLIENT_T* mqtt_client_init() {
    MQTT_CLIENT_T *state = new MQTT_CLIENT_T();
    if (!state) {
        DEBUG_printf("failed to allocate state\n");
        return nullptr;
    }
    state->receiving = 0;
    state->received = 0;
    return state;
}
 
void dns_found(const char *name, const ip_addr_t *ipaddr, void *callback_arg) {
    MQTT_CLIENT_T *state = (MQTT_CLIENT_T*)callback_arg;
    DEBUG_printf("DNS query finished with resolved addr of %s.\n", ip4addr_ntoa(ipaddr));
    state->remote_addr = *ipaddr;
}

void run_dns_lookup(MQTT_CLIENT_T *state) {
    DEBUG_printf("Running DNS query for %s.\n", MQTT_SERVER_HOST);

    cyw43_arch_lwip_begin();
    err_t err = dns_gethostbyname(MQTT_SERVER_HOST, &(state->remote_addr), dns_found, state);
    cyw43_arch_lwip_end();

    if (err == ERR_ARG) {
        DEBUG_printf("failed to start DNS query\n");
        return;
    }

    if (err == ERR_OK) {
        DEBUG_printf("no lookup needed\n");
        return;
    }

    while (state->remote_addr.addr == 0) {
        cyw43_arch_poll();
        sleep_ms(1);
    }
}

static void mqtt_connection_cb(mqtt_client_t *client, void *arg, mqtt_connection_status_t status) {
    MQTT_CLIENT_T *state = (MQTT_CLIENT_T *)arg;
    if (status != 0) {
        DEBUG_printf("Error during connection: err %d.\n", status);
    } else {
        DEBUG_printf("MQTT connected.\n");
    }
}

void mqtt_pub_request_cb(void *arg, err_t err) {
    MQTT_CLIENT_T *state = (MQTT_CLIENT_T *)arg;
    DEBUG_printf("mqtt_pub_request_cb: err %d\n", err);
    state->receiving = 0;
    state->received++;
}

err_t mqtt_test_publish(MQTT_CLIENT_T *state, const char *message)
{
  char buffer[128];

  #if MQTT_TLS
  #define TLS_STR "TLS"
  #else
  #define TLS_STR ""
  #endif

  sprintf(buffer, message, state->received, state->counter, TLS_STR);

  err_t err;
  u8_t qos = 2; /* 0 1 or 2, see MQTT specification */
  u8_t retain = 0;
  cyw43_arch_lwip_begin();
  printf("MQTT PUBLISH\n");
  err = mqtt_publish(state->mqtt_client, "picow", buffer, strlen(buffer), qos, retain, mqtt_pub_request_cb, state);
  cyw43_arch_lwip_end();
  if(err != ERR_OK) {
    DEBUG_printf("Publish err: %d\n", err);
  }

  return err;
}

void mqtt_test_conn_config_cb(void *conn) {
    #if MQTT_TLS
    mbedtls_ssl_set_hostname(altcp_tls_context(static_cast<struct altcp_pcb *>(conn)), MQTT_SERVER_HOST);
    #endif
}

err_t mqtt_test_connect(MQTT_CLIENT_T *state) {
    DEBUG_printf("mqtt_test_connect inside\n");
    struct mqtt_connect_client_info_t ci;
    err_t err;

    memset(&ci, 0, sizeof(ci));

    ci.client_id = "pico";
    ci.client_user = "";
    ci.client_pass = "";
    ci.keep_alive = 60;
    ci.will_topic = "picow";
    ci.will_msg = NULL;
    ci.will_retain = 0;
    ci.will_qos = 0;

    #if MQTT_TLS

    struct altcp_tls_config *tls_config;
  
    #if defined(CRYPTO_CA) && defined(CRYPTO_KEY) && defined(CRYPTO_CERT)
    DEBUG_printf("Setting up TLS with 2wayauth.\n");
    tls_config = altcp_tls_create_config_client_2wayauth(
        (const u8_t *)ca, 1 + strlen((const char *)ca),
        (const u8_t *)key, 1 + strlen((const char *)key),
        (const u8_t *)"", 0,
        
        (const u8_t *)cert, 1 + strlen((const char *)cert)
    );
    #elif defined(CRYPTO_CERT)
    DEBUG_printf("Setting up TLS with cert.\n");
    tls_config = altcp_tls_create_config_client((const u8_t *) cert, 1 + strlen((const char *) cert));
    #endif

    if (tls_config == NULL) {
        DEBUG_printf("Failed to initialize config\n");
        return -1;
    }

    ci.tls_config = tls_config;
    #endif

    //err = mqtt_client_connect(state->mqtt_client, &(state->remote_addr), MQTT_SERVER_PORT, mqtt_connection_cb, state, &ci, mqtt_test_conn_config_cb);
    DEBUG_printf("mqtt_client_connect\n");
    err = mqtt_client_connect(state->mqtt_client, &(state->remote_addr), MQTT_SERVER_PORT, mqtt_connection_cb, state, &ci);

    if (err != ERR_OK) {
        DEBUG_printf("mqtt_connect return %d\n", err);
    }
    DEBUG_printf("ERR_OK");
    return err;
}

void mqtt_run_test(MQTT_CLIENT_T *state) {
    DEBUG_printf("mqtt_run_test\n");

    adc_init();
    adc_gpio_init(28);
    
    ei_printf("EI_CLASSIFIER_DSP_INPUT_FRAME_SIZE: %.3f\n", EI_CLASSIFIER_DSP_INPUT_FRAME_SIZE);
    ei_printf("EI_CLASSIFIER_RAW_SAMPLES_PER_FRAME: %.3f\n", EI_CLASSIFIER_RAW_SAMPLES_PER_FRAME);


    state->mqtt_client = mqtt_client_new();

    //char* message = "";
    const char *message = "";

    if (state->mqtt_client == NULL) {
        DEBUG_printf("Failed to create new mqtt client\n");
        return;
    }

    if (mqtt_test_connect(state) == ERR_OK) {
        while (true) {

            ei_printf("\nStarting inferencing in 2 seconds...\n");
            sleep_ms(2000);
            cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
            ei_printf("Sampling...\n");

            // Allocate a buffer here for the values we'll read from the IMU
            float buffer[EI_CLASSIFIER_DSP_INPUT_FRAME_SIZE] = { 0 };

            for (size_t ix = 0; ix < EI_CLASSIFIER_DSP_INPUT_FRAME_SIZE; ix += EI_CLASSIFIER_RAW_SAMPLES_PER_FRAME) {
                // Determine the next tick (and then sleep later)

                uint64_t next_tick = ei_read_timer_us() + (EI_CLASSIFIER_INTERVAL_MS * 1000);
                //ei_printf("Loop: %.3f\n", next_tick - ei_read_timer_us());

                buffer[ix] = readAxisAccelation (2);
                buffer[ix + 1] = readAxisAccelation (2);
                buffer[ix + 2] = readAxisAccelation (2);
     
                buffer[ix + 0] *= CONVERT_G_TO_MS2;
                buffer[ix + 1] *= CONVERT_G_TO_MS2 * 0.2;
                buffer[ix + 2] *= CONVERT_G_TO_MS2 * 0.5;

     
                //sleep_us(next_tick - ei_read_timer_us());
            }

            // Turn the raw buffer in a signal which we can the classify
            signal_t signal;
            int err = numpy::signal_from_buffer(buffer, EI_CLASSIFIER_DSP_INPUT_FRAME_SIZE, &signal);
            if (err != 0) {
                ei_printf("Failed to create signal from buffer (%d)\n", err);
                //return 1;
            }

            // Run the classifier
            ei_impulse_result_t result = { 0 };
     
            err = run_classifier(&signal, &result, debug_nn);
            if (err != EI_IMPULSE_OK) {
                ei_printf("ERR: Failed to run classifier (%d)\n", err);
                //return 1;
            }
     
            // print the predictions
            ei_printf("Predictions ");

            ei_printf("(DSP: %d ms., Classification: %d ms., Anomaly: %d ms.)",
                result.timing.dsp, result.timing.classification, result.timing.anomaly);
            ei_printf(": \n");
            for (size_t ix = 0; ix < EI_CLASSIFIER_LABEL_COUNT; ix++) {
                ei_printf("    %s: %.5f\n", result.classification[ix].label, result.classification[ix].value);
            }

            #if EI_CLASSIFIER_HAS_ANOMALY == 1
                ei_printf("    anomaly score: %.3f\n", result.anomaly);
            #endif
            cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);

            
            //OFF
            if ((result.classification[1].value >= result.classification[0].value)&&(result.classification[1].value >=result.classification[2].value)) {
                message = "OFF";
            }
            //ON
            if ((result.classification[2].value >= result.classification[0].value)&&(result.classification[2].value >=result.classification[1].value)) {          
                message = "ON";
            }
            //NONE
            if ((result.classification[0].value >= result.classification[1].value)&&(result.classification[0].value >=result.classification[2].value)) {          
                message = "";
            }


            if (message != NULL && strlen(message) > 0) {
                cyw43_arch_poll();
                sleep_ms(1);

                if (mqtt_client_is_connected(state->mqtt_client)) {
                    cyw43_arch_lwip_begin();
                    state->receiving = 1;

                    if (mqtt_test_publish(state, message) == ERR_OK) {
                        ei_printf("published %d\n", state->counter);
                        state->counter++;
                    } // else ringbuffer is full and we need to wait for messages to flush.
                    cyw43_arch_lwip_end();
                } else {
                    ei_printf(".");
                }

                // MEM_STATS_DISPLAY();
                // MEMP_STATS_DISPLAY(0);
                // MEMP_STATS_DISPLAY(1);
            }
        }
    }
}


void wait_for_usb() {
    while (!tud_cdc_connected()) {
        DEBUG_printf(".");
        sleep_ms(500);
    }
    DEBUG_printf("usb host detected\n");
}


 
int main()
{
    stdio_init_all();

    //wait_for_usb();
    
    if (cyw43_arch_init_with_country(CYW43_COUNTRY_UK)) {
        DEBUG_printf("failed to initialise\n");
        return 1;
    }

    DEBUG_printf("initialised\n");

    cyw43_arch_enable_sta_mode();

    if (cyw43_arch_wifi_connect_timeout_ms(ssid, pass, CYW43_AUTH_WPA2_AES_PSK, 30000)) {
        DEBUG_printf("failed to  connect.\n");
        return 1;
    } else {
        DEBUG_printf("Connected.\n");
    }

    MQTT_CLIENT_T *state = mqtt_client_init();

    run_dns_lookup(state);
 
    mqtt_run_test(state);

    cyw43_arch_deinit();

    return 0;
}
