# Dataplane Router

---

## General Description

This project implements the core functionalities of a dataplane router, closely following the assignment requirements. The implementation includes:

- **Longest Prefix Match (LPM)** using **binary search** for efficient route lookup.  
- Routing process handling incoming packets and forwarding them appropriately.  
- Implementation of **ARP protocol** with a dynamic ARP cache (no static ARP table).  
- Implementation of **ICMP protocol**, including echo requests/replies and error handling.

The solution passes all provided tests and builds upon concepts learned and implemented in laboratory sessions.

---

## Code Structure

- The code is divided into a **main** function and several helper functions that handle specific cases encountered by the router.
- The **main** function performs general packet validation and delegates tasks to the appropriate functions based on packet header information.

---

## Key Functions

- `get_best_route_binary`:  
  Performs a binary search to implement the Longest Prefix Match algorithm on the sorted routing table.

- `cmp`:  
  Comparator function used with `qsort` to sort the routing table by prefixes and masks, preparing it for binary search.

- `send_icmp_time_exceeded`:  
  Sends an ICMP "Time Exceeded" message when the TTL of a packet is less than or equal to 1.

- `respond_to_icmp_echo`:  
  Handles incoming ICMP Echo Requests by sending back Echo Replies.

- `send_icmp_destination_unreachable`:  
  Invoked when `get_best_route_binary` returns null (no next hop found), sending an ICMP "Destination Unreachable" message.

- `send_arp_request`:  
  Sends an ARP request when the MAC address of the next hop is not present in the router’s ARP cache.

- `respond_to_arp_request`:  
  Handles ARP requests received by the router; if the router is the destination, it sends an ARP reply.

- `process_arp_reply`:  
  Processes incoming ARP replies by adding the MAC address to the ARP cache and sending any queued packets waiting for this MAC.

---

## Additional Notes

- Extensive inline comments are included throughout the code to aid debugging and clarify program flow.
- The router does **not** use a static ARP table, instead dynamically managing an ARP cache.
- The implementation covers all cases required by the assignment and handles errors gracefully using ICMP messages.

---
