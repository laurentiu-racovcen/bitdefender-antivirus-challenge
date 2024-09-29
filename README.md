# Task 1

> Detection of malicious URLs occurs by means of an existing database of malicious domains and by observing the presence/absence of certain substrings in the URL.

Initially, the following global variables are declared:
1. A structure ("url_structure") with 2 pointers (char *host; char *path;) that will be used to allocate memory for further URL processing;
2. The struct variable "url" of type "url_structure" is declared.
3. The variables needed by the "getline" function;
4. The variable "result" in which the verdict of each URL will be stored.

## **"main" function**

1. Define 2 variables of type FILE* (fin, fout) to access files:
- urls.in, from which each URL, to be processed, is read;
- urls-predictions.out, in which the verdict for each URL in the urls.in file is written;
2. Using a while loop and the "getline" function, each URL in the "urls.in" file is read, and this URL is stored in the "url_current" vector, which has dynamically allocated memory for a URL of up to 500 characters;
3. In the "while" loop the void function "task1_part1()" is called, in which the value of the verdict (in the variable "result") can be modified;
4. If the result becomes 1, this value is displayed in "urls-predictions.out", and if not, the void function "task1_part2()" is called and the value of "result" is checked again and displayed;
5. Release the dynamically allocated memory;
6. Exiting the while loop, the program releases the dynamically allocated memory in "url_current";
7. Close the "fin" and "fout" files.

## **"task1_part1(void)" function**

> Within the task1_part1(void) function, the first part of detecting malicious URLs (in the URL Host) takes place. In this part, it checks if the URL Host contains a domain from the database or if the Host contains certain strings.

The detection was performed using the following algorithm:
1. Allocate memory for the read URL (in "url.host" and "url.path");
2. the host of the current URL is stored in "url.host";
3. Define the variable of type FILE* (fin_tests) to access the "domains_database" file, where the malicious domains are located
4. Use a while loop to check if the host of the current URL contains a domain in the database. If it does, result is set to 1;
5. Next, check whether one of the following occurs:
- the host of the current URL contains the substring ".ru"
- the host contains at least one digit
- the host contains only dots and digits
- whether the host contains the string "ypa"
6. Close the "fin_tests" file.

## **"task1_part2(void)" function**

> In task1_part2(void) the second part of the malicious URL detection (in the PATH of the URL) takes place. In this part it checks if the path of the URL contains a file with an extension (different from: ".html", ".htm", ".php"), which can be malicious.

The detection was performed using the following algorithm:
1. the path of the current URL is stored in "url.path";
2. The pointer "char *p = NULL" is declared, in which the address of the last '.' in "url.path" is stored if '.' exists in the URL path;
5. Next, check that all of the following conditions occur in the URL path:
- the last 4 characters are not 'html'
- the next 5 characters after the last dot found are not html?
- the last 3 characters of 'url.path' are not htm
- the next 4 characters after the last dot are not htm?
- last 3 characters in "url.path" are not php
- the next 4 characters after the last dot are not php?
if all conditions have been met: result = 1;
if all conditions have not been met: result = 0.

# Task 2

> In Task 2, the detection of malicious traffic through a database of traffic captures and their results (0 or 1) takes place. Thus, I've learned certain conditions under which traffic is benign or malicious, and according to these, the results were displayed.

Initially, the following global variables are declared:
1. A structure ("traffic_structure") in which 4 pointers (char *response_port; char *flow_duration; char *flow_pkts_payload; char *fwd_pkts_tot;) are declared, with which memory will be allocated for further traffic processing;
2. A struct variable "traffic" of type "traffic_structure".

## **"main" function**

1. Define 2 variables of type FILE* (tin, tout) to access the files:
- traffic.in, from which each traffic capture to be processed is read;
- traffic-predictions.out, to write the verdict for each traffic capture in the "traffic.in" file;
2. Using a while loop and the getline function, each entry in the traffic.in file is read, and this traffic capture is stored in the traffic_current vector, which has dynamically allocated memory for an entry of up to 500 characters;
3. In the "while" loop the void functions "task2_part1()" and "task2_part2()" are called, in which the value of the verdict (in the variable "result") can be changed;
4. The value of "result" is displayed in the file "traffic-predictions.out";
5. The dynamically allocated memory is freed;
6. Exiting the while loop, the program releases the dynamically allocated memory in "traffic_current";
7. Close the files "tin" and "tout".

## **"task2_part1(void)" function**

> Within the task2_part1(void) function, the first part of the malicious traffic detection takes place, using a database. In this part the values corresponding to the traffic capture and columns "flow_duration", "flow_pkts_payload.avg" are checked. Depending on these values, the result is displayed 0 - if the traffic is benign or 1 - if the traffic is malicious.

The detection was performed using the following algorithm:
1. Allocate memory for the details in the "flow_duration" column of the read traffic capture;
2. The line corresponding to the traffic capture is traversed, and after passing the 3rd comma, the position of the first character of the value in the "flow_duration" column is copied to "j";
3. In traffic.flow_duration copy the value that is in the "flow_duration" column;
4. Declare the variable "k_2p", which holds the number of ":" characters in "flow_duration" to find the seconds corresponding to the duration;
5. If "flow_duration" is greater than one second, then result is assigned the value 1;
6. Allocate memory for the details in the "flow_pkts_payload.avg" column of the read traffic capture;
7. Go through the line corresponding to the traffic capture, and after passing the 15th comma, copy to "j" the position of the first character of the value in the "flow_pkts_payload.avg" column;
8. In traffic.flow_pkts_payload, copy the value from the column "flow_pkts_payload.avg";
9. Check if the length of the string in the "flow_pkkts_payload" column is 3 and if this string is "0.0". If these conditions are met, result is assigned the value 0.

## **"task2_part2(void)" function**

> Within the task2_part2(void) function, the second part of the malicious traffic detection takes place, using a database. In this part the values corresponding to the traffic capture and columns "fwd_pkts_tot", "response_port" are checked. Depending on these values, the result is displayed 0 - if the traffic is benign or 1 - if the traffic is malicious.

The detection was performed using the following algorithm:
1. Allocate memory for the details in the "fwd_pkts_tot" column of the read traffic capture;
2. The line corresponding to the traffic capture is traversed, and after passing the 4th comma, the position of the first character of the value that is in the "fwd_pkts_tot" column is copied to "j";
3. In traffic.fwd_fwd_pkts_tot copy the value that is in the "fwd_pkts_tot" column;
4. If the number of forward packets is greater than 35, result is assigned the value 1;
5. Allocate memory for the details in the "response_port" column of the read traffic capture;
6. Go through the line corresponding to the traffic capture, and after passing the 2nd comma, copy to "j" the position of the first character of the value in the "response_port" column;
7. In traffic.response_port, copy the value from the "response_port" column;
8. Turn the string "traffic.response_port" into an integer. Then, if it equals 1947 or 138 (these numbers represent the port), then the result is assigned the value 1.
