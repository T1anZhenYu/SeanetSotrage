#ifndef _USER_CONFIG_H_
#define _USER_CONFIG_H_
#include <stdint.h>

/**
 * Get the IPv6 address of the global resolve node.
 *
 * @param ipv6_addr
 *   Output with the IPv6 address of the enhanced resolve node.
 *   It's the caller's responsibility to ensure the pre-allocated buffer is
 * sufficient (16 Bytes).
 * @return
 *   - 0: Success.
 *   - -EINVAL: The parameters are invalid.
 *   - -ENOENT: Interface is not configured.
 */
int sc_config_global_resolve_node_get(uint8_t* ipv6_addr);

/**
 * Get the IPv6 address and the latency restriction of the enhanced resolve
 * node.
 *
 * @param ipv6_addr
 *   Output with the IPv6 address of the enhanced resolve node.
 *   It's the caller's responsibility to ensure the pre-allocated buffer is
 * sufficient (16 Bytes).
 * @param latency
 *   Output with the latency restriction of the enhanced resolve node.
 * @return
 *   - 0: Success.
 *   - -EINVAL: The parameters are invalid.
 *   - -ENOENT: Interface is not configured.
 */
int sc_config_enhanced_resolve_node_get(uint8_t* ipv6_addr, int16_t* latency);

/**
 * Get the IPv6 address and the link layer address of the interface specified by
 * ifname.
 *
 * @param ifname
 *   The interface name to check with.
 * @param ether_addr
 *   Output with the link layer address of the specified interface.
 *   It's the caller's responsibility to ensure the pre-allocated buffer is
 * sufficient (6 Bytes).
 * @param ipv6_addr
 *   Output with the IPv6 address of the specified interface.
 *   It's the caller's responsibility to ensure the pre-allocated buffer is
 * sufficient (16 Bytes).
 * @return
 *   - 0: Success.
 *   - -EINVAL: The parameters are invalid.
 *   - -ENOENT: Interface is not configured.
 */
int sc_config_ethdev_get(const char* ifname, uint8_t* ether_addr,
                         uint8_t* ipv6_addr);

#endif  // !_USER_CONFIG_H_
