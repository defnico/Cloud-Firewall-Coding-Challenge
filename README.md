To run interactively:<br/>
python -i firewall.py<br/>
fw = Firewall('firewall.csv')<br/>
print fw.accept_packet("inbound", "tcp", 80, "192.168.1.2")

I was looking to set up the system to be able to solve it efficiently as a brute force linear search through all the rules
didn't seem to be the main objective of the challenge. My approach was to first sort all the rules by the start values
of the port ranges and keep the associated ip ranges. We can then merge the ip ranges and sort them as well.
This will allow binary search to find the port range and then another binary search to find the ip_range.
Using sorted lists takes advantage of contiguous memory and so is the most memory efficient solution compared to hashing
or trees. Hashing could potentially be a faster lookup except it wasn't clear to me how to look up intervals using
using hashing.

Finding the port range is done with binary search. I didn't have time to the same for ip address lookup and so just did
that using linear lookup (and left TODOs in the code where that would happen).

For testing, I ran the given cases and added some more. The main complex cases which I also did not handle was
overlapping port ranges or ip ranges as they would require splitting up the intervals, which I did not have time
to implement but left TODOs as well.
I also tested loading an empty file to make sure that looking up in empty arrays worked correctly.
In general more testing is needed to ensure handle each combination of ports before, inside, and after a port range of
length 1 and larger than length 1. The same needs to be done for ip address.

This was an interesting problem which I first started out in C++ as that would be most efficient to execute
and is the language I've used the most. For code that may run in specialized hardware for speed,
that is often done in C/C++. But I realized that all the parsing is not easy to do in that language and so switched to
Python. I used StackOverflow to review Python syntax and see if there was a interval lookup library which there doesn't
seem to be. I have to say because Python is not my main language, this exercise took me a fair amount of time, but
I enjoyed it and learned a lot in the process.

Finally, after looking over the different team descriptions, I have a slight preference for the Data team, but they
are seem interesting.
