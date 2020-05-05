#ifndef __bbr_common_h_
#define __bbr_common_h_

// If greater than zero, mean RTT variation is multiplied by the specified
// factor and added to the congestion window limit.
#define kBbrRttVariationWeight 0.0f

// Congestion window gain for QUIC BBR during PROBE_BW phase.
#define kProbeBWCongestionWindowGain 2.0f

// The maximum packet size of any QUIC packet, based on ethernet's max size,
// minus the IP and UDP headers. IPv6 has a 40 byte header, UDP adds an
// additional 8 bytes.  This is a total overhead of 48 bytes.  Ethernet's
// max packet size is 1500 bytes,  1500 - 48 = 1452.
#define kMaxPacketSize 1452

// Default maximum packet size used in the Linux TCP implementation.
// Used in QUIC for congestion window computations in bytes.
#define kDefaultTCPMSS 1200
// Constants based on TCP defaults.
#define kMaxSegmentSize kDefaultTCPMSS

// The gain used for the slow start, equal to 4ln(2).
#define kHighGain 2.77f
// The gain used in STARTUP after loss has been detected.
// 1.5 is enough to allow for 25% exogenous loss and still observe a 25% growth
// in measured bandwidth.
#define kStartupAfterLossGain 1.5
// The gain used to drain the queue after the slow start.
#define kDrainGain  (1.f / kHighGain)

// The length of the gain cycle.
#define kGainCycleLength 8
// The size of the bandwidth filter window, in round-trips.
#define kBandwidthWindowSize (kGainCycleLength + 2)

// The time after which the current min_rtt value expires.
#define kMinRttExpirySeconds 10
// The minimum time the connection can spend in PROBE_RTT mode.
#define kProbeRttTimeMs 200
// If the bandwidth does not increase by the factor of |kStartupGrowthTarget|
// within |kRoundTripsWithoutGrowthBeforeExitingStartup| rounds, the connection
// will exit the STARTUP mode.
#define kStartupGrowthTarget 1.25
// Coefficient to determine if a new RTT is sufficiently similar to min_rtt that
// we don't need to enter PROBE_RTT.
#define kSimilarMinRttThreshold 1.125

#define kInitialBandwidthKbps 300

#define kInitialCongestionWindowPackets 4
// The minimum CWND to ensure delayed acks don't reduce bandwidth measurements.
// Does not inflate the pacing rate.
#define kDefaultMinCongestionWindowPackets 4
#define kDefaultMaxCongestionWindowPackets 2000

typedef struct
{
	int64_t		at_time;
	int32_t		min_rate;
	int32_t		max_rate;
}bbr_target_rate_constraint_t;

typedef struct
{
	int64_t		send_time;
	int64_t		recv_time;
	size_t		size;
	int64_t		seq;
	size_t		data_in_flight;
}bbr_packet_info_t;

typedef struct
{
	int64_t		receive_time;
	int32_t		bandwidth;
}bbr_remote_bitrate_report_t;

typedef struct
{
	int64_t		receive_time;
	int64_t		round_trip_time;
	int			smoothed;
}bbr_rtt_update_t;

typedef struct
{
	int64_t			at_time;
	size_t			data_window;
	int64_t			time_window;
	size_t			pad_window;
}bbr_pacer_config_t;

typedef struct
{
	int64_t			at_time;
	int				network_available;
}bbr_network_availability_t;

typedef struct
{
	int64_t			at_time;
	int32_t			bandwidth;
	int64_t			rtt;
	int64_t			bwe_period;

	int32_t			target_rate;
}bbr_target_transfer_rate_t;

typedef struct
{
	size_t						congestion_window;
	size_t						data_in_flight;
	bbr_pacer_config_t			pacer_config;
	bbr_target_transfer_rate_t  target_rate;
}bbr_network_ctrl_update_t;

#define MAX_BBR_FEELBACK_COUNT	128


typedef struct
{
	uint16_t				seq;
	uint16_t				delta_ts;
}bbr_sampler_t;
#endif



