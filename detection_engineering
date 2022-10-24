# SOC detection engineering and management

# TOC

* Generic recommended approach
* PDCA applied to SOC
* How to feed the Plan (detection engineering)


# Generic recommended approach

## PDCA multi-loop:

As per [Wikipedia](https://en.wikipedia.org/wiki/PDCA#/media/File:PDCA-Multi-Loop.png)


# PDCA being applied to SOC:

## Plan:

### Sensors:
* Determine which sensors or endpoint/app logs, you miss in terms of detection capabilities
* Determine how to generate and ingest their logs in the SIEM
* Build a projet agenda

### SIEM rules:
* Determine which detection logic you miss, directly in the SIEM;
* Build a project agenda.


## Do:

### Sensors:
* Ingest the logs of the security sensor, or endpoint/app logs, that you previously identified;
* Make sure your data ingestion is compliant with the datamodel you use.


### SIEM rules:
* create the detection rules (SIEM searches) that match your previously identified needs;
* create the alert objects in the SIEM or SIRP, to contain the contents of the SIEM searches in case something is found;


## Check:

### Logs:
* Make sure your data ingestion is compliant with the datamodel you use;

### SIEM rules [first run for the assessed detection capabilities]:
* Test the detection logics with narrowed use cases (specific events, generated on demand).

### SIEM rules [following runs for the assessed detection capabilities]
* Assess your detection capabilities with purpleteaming
* Report your results and findings in purpose-built app like Vectr.

## Act:
* Fix everything that was previously identified as not working, or not matching your needs.

