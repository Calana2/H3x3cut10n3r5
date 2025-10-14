# Remember Me

This challenge was simply steganography:

1. "RememberMe.jpg" had a zip file protected by password. The correct password was in the challenge description.
2. The zip had the file "flag.mp4" with a rar file inside.
3. The rar had a pcap capture file named "giveup.pcapng".
4. In the capture there was a shortened url that redirected to a file in Google Drive.
5. The file in Drive, called "lyrics.txt" had unicode steganography with zero-width characters.

`EnXp{y0u_r34lly_didnt_g1v3_up}`
