#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdint.h>

#define PORT 2023
#define MAX_SATELLITES 16
#define MAX_PAYLOAD_SIZE 8192

// CCSDS (Consultative Committee for Space Data Systems) Protocol Headers
typedef struct __attribute__((packed)) {
    uint16_t packet_version_number : 3;
    uint16_t packet_type : 1;
    uint16_t sec_header_flag : 1;
    uint16_t apid : 11;              // Application Process ID
    uint16_t sequence_flags : 2;
    uint16_t packet_sequence_count : 14;
    uint16_t packet_data_length;     // Length of data field - 1
} ccsds_primary_header_t;

// TC (Telecommand) Secondary Header
typedef struct __attribute__((packed)) {
    uint8_t  version_number : 4;
    uint8_t  bypass_flag : 1;
    uint8_t  control_command_flag : 1;
    uint8_t  spare : 2;
    uint8_t  spacecraft_id;
    uint8_t  virtual_channel_id : 6;
    uint8_t  reserved : 2;
    uint8_t  map_id;
} tc_secondary_header_t;

// TM (Telemetry) Secondary Header
typedef struct __attribute__((packed)) {
    uint8_t  version_number : 4;
    uint8_t  spacecraft_id : 4;
    uint8_t  virtual_channel_id : 3;
    uint8_t  ocf_flag : 1;
    uint8_t  master_channel_frame_count : 4;
    uint8_t  virtual_channel_frame_count;
    uint16_t data_field_status;
} tm_secondary_header_t;

// Satellite Command Types
typedef enum {
    CMD_ATTITUDE_CONTROL = 0x10,
    CMD_ORBIT_MANEUVER = 0x20,
    CMD_PAYLOAD_CONTROL = 0x30,
    CMD_SUBSYSTEM_CONFIG = 0x40,
    CMD_DATA_DOWNLOAD = 0x50,
    CMD_EMERGENCY_SAFE = 0xFF
} satellite_command_type_t;

// Attitude Control Command
typedef struct __attribute__((packed)) {
    uint8_t command_type;
    uint8_t target_mode;             // 0=SAFE, 1=POINT, 2=SPIN, 3=DETUMBLE
    float target_quaternion[4];      // Attitude quaternion
    float angular_velocity[3];       // Target angular velocity
    uint16_t control_duration;       // Duration in seconds
    uint8_t thruster_config;         // Thruster configuration bitmask
} attitude_control_cmd_t;

// Orbit Maneuver Command
typedef struct __attribute__((packed)) {
    uint8_t command_type;
    uint8_t maneuver_type;           // 0=PROGRADE, 1=RETROGRADE, 2=NORMAL, 3=RADIAL
    float delta_v[3];                // Delta-V vector in m/s
    uint32_t burn_start_time;        // Burn start time (mission elapsed time)
    uint16_t burn_duration;          // Burn duration in seconds
    uint8_t engine_selection;        // Engine selection bitmask
} orbit_maneuver_cmd_t;

// Payload Control Command
typedef struct __attribute__((packed)) {
    uint8_t command_type;
    uint8_t payload_id;              // Payload identifier
    uint8_t operation_mode;          // Operation mode
    uint32_t data_rate;              // Data rate in bps
    uint16_t integration_time;       // Integration time in ms
    uint8_t filter_config[8];        // Filter configuration
    char target_coordinates[32];     // Target coordinates string
} payload_control_cmd_t;

// Data Download Command
typedef struct __attribute__((packed)) {
    uint8_t command_type;
    uint8_t data_type;               // 0=TELEMETRY, 1=PAYLOAD, 2=HOUSEKEEPING
    uint32_t start_time;             // Start time for data
    uint32_t end_time;               // End time for data
    uint16_t max_packets;            // Maximum number of packets
    uint8_t priority;                // Download priority
    char file_pattern[64];           // File pattern for download
} data_download_cmd_t;

// Satellite state structure
typedef struct {
    uint8_t satellite_id;
    char satellite_name[16];
    uint8_t status;                  // 0=OFFLINE, 1=SAFE, 2=NOMINAL, 3=EMERGENCY
    float position[3];               // Position in km
    float velocity[3];               // Velocity in km/s
    float attitude[4];               // Attitude quaternion
    uint32_t last_contact_time;
    uint16_t battery_level;          // Battery level in percentage
    float temperature;               // Temperature in Celsius
} satellite_state_t;

static satellite_state_t satellites[MAX_SATELLITES];
static int active_satellites = 0;

// VULNERABLE FUNCTION 1: Process attitude control command
void process_attitude_control(uint8_t sat_id, uint8_t* cmd_data, uint16_t cmd_length) {
    attitude_control_cmd_t* cmd = (attitude_control_cmd_t*)cmd_data;
    float attitude_buffer[16];       // Stack buffer for attitude calculations
    float control_matrix[9];         // 3x3 control matrix
    
    printf("[SAT-%02d] Processing attitude control command\n", sat_id);
    printf("[DEBUG] Command length: %d, Target mode: %d\n", cmd_length, cmd->target_mode);
    
    // VULNERABILITY 1: No validation of cmd_length vs expected structure size
    // Attacker can send oversized cmd_length causing buffer overflow
    
    // Copy quaternion data for processing
    memcpy(attitude_buffer, cmd->target_quaternion, cmd_length - 1);  // CWE-787: Out-of-bounds Write
    
    // Copy angular velocity (assumes fixed offset, but cmd_length could be manipulated)
    memcpy(attitude_buffer + 4, cmd->angular_velocity, 12);
    
    // VULNERABILITY 2: No bounds checking on thruster_config
    // thruster_config used as array index without validation
    float thruster_power_levels[8] = {0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8};
    float selected_power = thruster_power_levels[cmd->thruster_config];  // CWE-787: Potential out-of-bounds read
    
    printf("[SAT-%02d] Attitude control configured, power level: %.2f\n", sat_id, selected_power);
    
    // Update satellite state
    if (sat_id < MAX_SATELLITES) {
        memcpy(satellites[sat_id].attitude, cmd->target_quaternion, 16);
        satellites[sat_id].status = 2;  // NOMINAL
    }
}

// VULNERABLE FUNCTION 2: Process orbit maneuver command
void process_orbit_maneuver(uint8_t sat_id, uint8_t* cmd_data, uint16_t cmd_length) {
    orbit_maneuver_cmd_t* cmd = (orbit_maneuver_cmd_t*)cmd_data;
    float trajectory_buffer[64];     // Stack buffer for trajectory calculations
    char maneuver_log[128];          // Log buffer
    
    printf("[SAT-%02d] Processing orbit maneuver command\n", sat_id);
    printf("[DEBUG] Maneuver type: %d, Burn duration: %d seconds\n", 
           cmd->maneuver_type, cmd->burn_duration);
    
    // VULNERABILITY 3: sprintf without bounds checking
    // If satellite name is too long, it will overflow maneuver_log
    sprintf(maneuver_log, "MANEUVER: Satellite %s executing %d-second burn", 
            satellites[sat_id].satellite_name, cmd->burn_duration);  // CWE-787: Buffer overflow
    
    // VULNERABILITY 4: Delta-V array copying without size validation
    // cmd_length could be manipulated to copy more data than buffer can hold
    memcpy(trajectory_buffer, cmd->delta_v, cmd_length - 5);  // CWE-787: Out-of-bounds Write
    
    // VULNERABILITY 5: Engine selection as array index
    float engine_efficiency[4] = {0.85, 0.90, 0.88, 0.92};
    float efficiency = engine_efficiency[cmd->engine_selection];  // CWE-787: Array index not validated
    
    printf("[SAT-%02d] Maneuver planned, efficiency: %.2f\n", sat_id, efficiency);
    
    // Update satellite state
    if (sat_id < MAX_SATELLITES) {
        memcpy(satellites[sat_id].velocity, cmd->delta_v, 12);
    }
}

// VULNERABLE FUNCTION 3: Process payload control command
void process_payload_control(uint8_t sat_id, uint8_t* cmd_data, uint16_t cmd_length) {
    payload_control_cmd_t* cmd = (payload_control_cmd_t*)cmd_data;
    uint8_t filter_buffer[32];       // Stack buffer for filter configuration
    char coordinate_buffer[64];      // Buffer for target coordinates
    
    printf("[SAT-%02d] Processing payload control command\n", sat_id);
    printf("[DEBUG] Payload ID: %d, Operation mode: %d\n", cmd->payload_id, cmd->operation_mode);
    
    // VULNERABILITY 6: Filter configuration copying without bounds check
    // cmd->filter_config could be manipulated via packet crafting
    memcpy(filter_buffer, cmd->filter_config, cmd_length - 15);  // CWE-787: Out-of-bounds Write
    
    // VULNERABILITY 7: String copying without length validation
    // target_coordinates field could be oversized, overflowing coordinate_buffer
    strcpy(coordinate_buffer, cmd->target_coordinates);  // CWE-787: Buffer overflow
    
    // VULNERABILITY 8: payload_id used as array index
    char* payload_names[4] = {"CAMERA", "SPECTROMETER", "RADAR", "LIDAR"};
    char* payload_name = payload_names[cmd->payload_id];  // CWE-787: Array bounds not checked
    
    printf("[SAT-%02d] Payload %s configured for coordinates: %s\n", 
           sat_id, payload_name, coordinate_buffer);
}

// VULNERABLE FUNCTION 4: Process data download command
void process_data_download(uint8_t sat_id, uint8_t* cmd_data, uint16_t cmd_length) {
    data_download_cmd_t* cmd = (data_download_cmd_t*)cmd_data;
    char file_list[256];             // Buffer for file list
    char download_queue[512];        // Buffer for download queue
    
    printf("[SAT-%02d] Processing data download command\n", sat_id);
    printf("[DEBUG] Data type: %d, Max packets: %d\n", cmd->data_type, cmd->max_packets);
    
    // VULNERABILITY 9: File pattern copying without bounds check
    // file_pattern field could be crafted to overflow file_list buffer
    strcpy(file_list, cmd->file_pattern);  // CWE-787: Buffer overflow
    
    // VULNERABILITY 10: sprintf with multiple unvalidated inputs
    sprintf(download_queue, "DOWNLOAD: Satellite %s, Type %d, Pattern %s, Priority %d", 
            satellites[sat_id].satellite_name, cmd->data_type, 
            cmd->file_pattern, cmd->priority);  // CWE-787: Multiple buffer overflows possible
    
    printf("[SAT-%02d] Download queued: %s\n", sat_id, download_queue);
}

// Main command processor
void process_satellite_command(uint8_t* packet_data, uint16_t packet_length) {
    ccsds_primary_header_t* primary_hdr = (ccsds_primary_header_t*)packet_data;
    tc_secondary_header_t* secondary_hdr = (tc_secondary_header_t*)(packet_data + sizeof(ccsds_primary_header_t));
    
    uint8_t sat_id = secondary_hdr->spacecraft_id;
    uint8_t* cmd_data = packet_data + sizeof(ccsds_primary_header_t) + sizeof(tc_secondary_header_t);
    uint16_t cmd_length = primary_hdr->packet_data_length;
    
    printf("[GROUND] Received command for satellite %d, length %d\n", sat_id, cmd_length);
    
    if (sat_id >= MAX_SATELLITES) {
        printf("[ERROR] Invalid satellite ID: %d\n", sat_id);
        return;
    }
    
    // Route command based on type
    uint8_t cmd_type = cmd_data[0];
    
    switch (cmd_type) {
        case CMD_ATTITUDE_CONTROL:
            process_attitude_control(sat_id, cmd_data, cmd_length);
            break;
        case CMD_ORBIT_MANEUVER:
            process_orbit_maneuver(sat_id, cmd_data, cmd_length);
            break;
        case CMD_PAYLOAD_CONTROL:
            process_payload_control(sat_id, cmd_data, cmd_length);
            break;
        case CMD_DATA_DOWNLOAD:
            process_data_download(sat_id, cmd_data, cmd_length);
            break;
        case CMD_EMERGENCY_SAFE:
            printf("[SAT-%02d] EMERGENCY SAFE MODE ACTIVATED\n", sat_id);
            satellites[sat_id].status = 1;  // SAFE
            break;
        default:
            printf("[ERROR] Unknown command type: 0x%02X\n", cmd_type);
            break;
    }
}

// Initialize satellite constellation
void initialize_satellites() {
    for (int i = 0; i < 8; i++) {
        satellites[i].satellite_id = i;
        snprintf(satellites[i].satellite_name, sizeof(satellites[i].satellite_name), "SAT-%02d", i);
        satellites[i].status = 2;  // NOMINAL
        satellites[i].position[0] = 6371.0 + 400.0 + (i * 50.0);  // Altitude in km
        satellites[i].position[1] = 0.0;
        satellites[i].position[2] = 0.0;
        satellites[i].velocity[0] = 0.0;
        satellites[i].velocity[1] = 7.66;  // Orbital velocity in km/s
        satellites[i].velocity[2] = 0.0;
        satellites[i].attitude[0] = 1.0;   // Quaternion w
        satellites[i].attitude[1] = 0.0;   // Quaternion x
        satellites[i].attitude[2] = 0.0;   // Quaternion y
        satellites[i].attitude[3] = 0.0;   // Quaternion z
        satellites[i].last_contact_time = time(NULL);
        satellites[i].battery_level = 85 + (i % 15);
        satellites[i].temperature = -15.0 + (i * 2.0);
    }
    active_satellites = 8;
    printf("[GROUND] Initialized %d satellites\n", active_satellites);
}

// Handle client connection
void handle_ground_station_client(int client_sock) {
    uint8_t packet_buffer[MAX_PAYLOAD_SIZE];
    
    printf("[GROUND] Ground station connected\n");
    
    while (1) {
        ssize_t bytes_received = recv(client_sock, packet_buffer, sizeof(packet_buffer), 0);
        if (bytes_received <= 0) {
            printf("[GROUND] Ground station disconnected\n");
            break;
        }
        
        printf("[GROUND] Received %zd bytes\n", bytes_received);
        
        // Process the satellite command packet
        process_satellite_command(packet_buffer, bytes_received);
        
        // Send acknowledgment
        char ack[] = "CMD_ACK";
        send(client_sock, ack, strlen(ack), 0);
    }
    
    close(client_sock);
}

int main() {
    int server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    // Initialize satellite constellation
    initialize_satellites();
    
    // Create socket
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("Socket creation failed");
        exit(1);
    }
    
    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    // Bind socket
    if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(1);
    }
    
    // Listen for connections
    if (listen(server_sock, 5) < 0) {
        perror("Listen failed");
        exit(1);
    }
    
    printf("[GROUND] Satellite Ground Station Controller listening on port %d\n", PORT);
    printf("[GROUND] Ready to receive satellite commands via CCSDS protocol\n");
    
    // Accept and handle ground station connections
    while (1) {
        client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("Accept failed");
            continue;
        }
        
        printf("[GROUND] Ground station connected from %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        // Handle ground station client
        handle_ground_station_client(client_sock);
    }
    
    close(server_sock);
    return 0;
}