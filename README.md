# NetSentry:Unauthorized-Background-Network-Activity-Detector

NetSentry seems like this simple security tool made in Python. Its pretty lightweight, which is good because you dont want something heavy running in the background all the time. Basically, it watches for those weird outbound connections that apps start without you knowing.

I think the main thing is detecting when background programs are trying to send stuff out, like logging it and reporting what is going on. You get to see in real time which processes are phoning home, you know, reaching out to servers without your okay. That part feels important for privacy, since it can help spot risks or even malware that might be hiding.

Its not perfect or anything, but it does make it easier to catch spyware before it does too much damage. Some apps just do that stuff quietly, and this tool points it out.

# Problem Statement:

In todays operating systems, its pretty common for them to hide whats going on with network stuff. Apps can just start talking in the background, and users might not even notice. That sort of thing happens a lot.

I think the biggest issue here is how it affects privacy and security. Without seeing that activity, risks build up, like data getting sent out without permission or some app connecting to bad commands. Command and control communication, thats the term, it feels risky.

This lack of visibility just makes everything more complicated, you know. Some people might say its for convenience, but im not totally sure.

# Objective
To build a system that:
-Correlates network traffic with specific system processes.

-Detects anomalous or unauthorized outbound connections.

-Visualizes network activity to provide actionable insights.

# Key Features:
-Process-to-Network Mapping: accurate correlation of every TCP/UDP connection to the exact Process ID (PID) and executable name responsible for it.

-Smart Whitelisting: An intelligent filtering system to distinguish between legitimate background traffic (e.g., Windows Update, Chrome) and suspicious activity, reducing alert fatigue.

-Real-Time Alerts: Immediate notifications (console/log) when an unknown process attempts to establish an outbound connection.

-Activity Dashboard: A visual summary of network traffic history, organized by process and destination IP.

