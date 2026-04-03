Cybersecurity & Network Security Internship Assessment 
Instructions 
This exam has three exercises that would be used to test your skill levels in designing, 
simulating, and securing systems in a real-world context. 
You will have to arrive at reasonable assumptions where required and exhibit security
conscious design and implementation. 
Among the three tasks, you will be obliged to do two tasks. 
In every chosen task, there should be: 
⚫ Complete implementation 
⚫ Proper documentation 
You must submit a detailed report (~2500 words) covering: 
⚫ Design approach 
⚫ Implementation details 
⚫ Analysis of results 
The report should be original, and AI-generated material should be reduced to a minimum 
(less than 10% similarity according to such tools as ZeroGPT or similar). 
A video walkthrough of your implementation is required, clearly demonstrating: 
⚫ System functionality 
⚫ Key components 
⚫ How requirements are satisfied 
Do not use ambiguous, misguided and inappropriate words in your submission. 
Provide appropriate screenshots, sample output, and session logs to prove your efforts. 
Include a reference list in case there is need to prove your design, etc. 
Submission guidelines: 
⚫ Upload all deliverables to a single Google Drive folder 
⚫ Do not zip the files 
⚫ Set access to “Anyone with the link can view” 
Task 1: Build a “Tamper-Evident Logging System” 
Objective 
Plug in a secure logging system where the entries in the logs cannot be modified, 
deleted or moved about without detection. This system must also guarantee integrity 
and reliability of logs just like the audit logging systems found in secure systems in 
the real world. 
Task Description 
You must design and develop a tamper evident log system to capture events like 
attempting to log in, user activity, or transactions. The general principle is that, after 
making a log entry, it is impossible to change it without leaving a trace of the editing. 
To do this, your system should create a security linkage between log entries. The log 
entries must be cryptographically connected to the last one (e.g. by means of hashing) 
so that any alteration of the earlier entries disrupts the chain and can be found. 
The system must be able to detect: 
in case a log entry has been altered If an entry has been deleted If entries have been 
re-arranged. 
It should also have a check system that can confirm the integrity of the complete log 
history and, where feasible, the point at which the tampering was done. 
Functional Requirements 
You should be able to support the following: 
Add Log Entries Add new events with associated information (timestamp, event type, 
description and so on) Should be securely attached to the last entry Must be efficient 
and scalable to many entries in the log Entries Must be consistent and free of any 
other logical constraints Add Log Entries Provide an interface to add new events with 
the appropriate information (timestamp, event type, description, etc.) Should be able 
to add a new event to the end of the log chain Must be efficient and scalable to a large 
number of entries in the log Entries Must be consistent and free of any other logical 
constraints Add Log Entries To ensure 
You need your implementation documented. The documentation ought to cover: 
System Design Explanation The mechanism works The tamper-evident mechanism is 
a data structure and algorithm Each log is represented by a simple record and an 
authentication tag The tamper-evident mechanism operates under the following 
assumptions and limitations Design Decisions and Goals The tamper-evident 
mechanism is a data structure and algorithm Each log is a simple record and an 
authentication tag The tamper-evident mechanism works as follows Usage 
Instructions How to run the tamper-evident mechanism How to add logs and verify 
their integrity Usage The tamper-evident mechanism is a data structure and algorithm 
Each log is represented by 
This task is aimed to simulate functioning of secure audit logging systems in real-life 
situations, its accountability and to avoid the manipulation of critical data without 
detection. 
Task 2 : Build a “Controlled Execution Sandbox” 
Objective 
This task aims to create a system, which can safely process untrusted user input and 
impose strong security constraints. 
Task Description 
You must create a program that takes in user input in the form of commands, scripts 
or expressions and run them in a controlled environment. The system should be 
designed in a way that that execution does not interfere with security by denying 
access to sensitive files or system resources, restricting the kind of operation that can 
be carried out, or restrict on the amount of time or resources used. In case a fully 
secure sandbox is hard to implement, you can model these constraints rationally, but 
you must explicitly show how unsafe inputs are handled and how they are responded 
to. 
The system must be able to recognize: 
The system is supposed to identify those who make unauthorized attempts to choose 
restricted resources, identify the execution of prohibited operations, and abnormal 
behaviors including excessive resource consumption or unlimited execution. 
Functional Requirements 
The system would permit running authorized inputs within specific restrictions and 
prohibit unsafe or other restricted actions. It must impose control over what is 
permissible and what is not, process any form of violation by terminating the 
execution or issuing warnings, and should give the user good feedback on whether 
their input was accepted or rejected. 
Documentation Requirement 
The whole implementation process should be well documented, the system design, 
how the restrictions are implemented, how the inputs are checked, and how the 
system responds to the violation or unsafe execution attempts. 
Task 3: Develop a Deception Based Security Mechanism. 
Objective 
This task aims to create a system, which identifies malicious conduct through 
deception methods. 
Task Description 
You must develop a system that comprises at least one element of deception, 
including a spoofed login interface, concealed file, or a dummy service/API that does 
not actually do anything but looks like it does. The system must observe 
communications with these components and consider any attempt of accessing the 
component as suspicious, as it is not intended to be utilized in the normal course of its 
functioning. 
The system must be able to recognize: 
The system must identify any contact with the fraudulent items, identify the behavior 
as suspicious or malicious and determine when an unauthorized access attempt has 
been made. 
Functional Requirements 
At least one trap must be defined and implemented into the system, and ongoing 
monitoring of interactions with the system must be created to generate alerts or 
responses when the trap is met. It must also clearly show how suspicious activity is 
identified and how it is managed. 
Documentation Requirement 
This needs to be documented correctly, detailing the design of the misleading 
components, how this is identified, and the manner in which the system is able to 
produce notifications or react to any suspicious activity. 
Grade 
Task Performance (40% per task) 
Documentation & Report (10% per 
task) 
80–100% 
Implementation is complete, secure, and well
designed. Demonstrates strong understanding of 
the concept with advanced features and accurate 
handling of all required scenarios. Clear evidence 
of analysis, testing, and correctness. 
Exceptionally well-structured report 
with clear explanation of design, 
implementation, and results. Strong 
analysis supported by examples or 
references. 
70–79% 
Well-implemented solution covering all core 
requirements. Most scenarios handled correctly 
with good demonstration of understanding and 
functionality. 
Clear and well-organized report 
explaining 
system 
design 
and 
working. Good level of analysis and 
clarity. 
Functional 
60–69% 
implementation 
covering 
basic 
requirements. Some limitations in handling edge 
cases 
or 
advanced 
features. 
50–59% 
Moderate 
understanding demonstrated. 
Basic implementation with partial functionality. 
Key features are present but not fully developed or 
consistent. 
Structured report with adequate 
explanation, but limited depth in 
analysis. 
Report is present but lacks clarity and 
detailed 
explanation. 
analysis. 
40–49% Partial or incomplete implementation. Weak 
Minimal 
understanding of the concept with limited 
Poorly structured report with limited 
explanation and analysis. 
Fail (30
39%) 
functionality. 
Very limited attempt with major issues in 
implementation. Core requirements not properly 
met. 
Very minimal documentation with 
little to no explanation. 
Fail 
29%) 
(0
No meaningful implementation. 
No proper documentation submitted. 