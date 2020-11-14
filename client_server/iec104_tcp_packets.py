# u frame types
STARTDT_ACT=0x07
STARTDT_CON=0x0b
STOPDT_ACT=0x13
STOPDT_CON=0x23
TESTFR_ACT=0x43
TESTFR_CON=0x83

#Sending Reasons
Cause_Act=0x06
Cause_Deact=0x08

#Control values
SCO_Off_Np_Ex=0x00
SCO_On_Np_Ex=0x01
SCO_Off_Sp_Ex=0x04
SCO_On_Sp_Ex=0x05
SCO_Off_Np_Se=0x80
SCO_On_Np_Se=0x81

DCO_Off_Np_Se=0x81
DCO_On_Np_Se=0x82

RCO_Down_Np_Se=0x81
RCO_Up_Np_Se=0x82

plist=[
	# yaotiao ----------------------------------------------------------
	('START','auto','if',[45,1,Cause_Act,4,3,(45000,SCO_Off_Np_Se)]),
	('START','auto','if',[45,1,Cause_Act,4,3,(45100,SCO_On_Np_Se)]),
	('START','auto','if',[45,1,Cause_Act,4,3,(45200,SCO_Off_Np_Se)]),
	('START','auto','if',[45,1,Cause_Act,4,3,(45300,SCO_On_Np_Se)]),
	('START','auto','if',[45,1,Cause_Act,4,3,(45400,SCO_Off_Np_Se)]),
	('START','auto','if',[45,1,Cause_Act,4,3,(45500,SCO_On_Np_Se)]),
	('START','auto','if',[45,1,Cause_Act,4,3,(45150,SCO_On_Np_Se)]),
	('START','auto','if',[46,1,Cause_Deact,4,3,(46000,DCO_Off_Np_Se)]),
	('START','auto','if',[46,1,Cause_Deact,4,3,(46100,DCO_On_Np_Se)]),
	('START','auto','if',[46,1,Cause_Deact,4,3,(46200,DCO_Off_Np_Se)]),
	('START','auto','if',[46,1,Cause_Deact,4,3,(46300,DCO_On_Np_Se)]),
	('START','auto','if',[46,1,Cause_Deact,4,3,(46400,DCO_Off_Np_Se)]),
	('START','auto','if',[46,1,Cause_Deact,4,3,(46500,DCO_On_Np_Se)]),
	('START','auto','if',[46,1,Cause_Deact,4,3,(46150,DCO_Off_Np_Se)]),
	('START','auto','if',[47,1,Cause_Deact,4,3,(47000,RCO_Down_Np_Se)]),
	('START','auto','if',[47,1,Cause_Deact,4,3,(47100,RCO_Up_Np_Se)]),
	('START','auto','if',[47,1,Cause_Deact,4,3,(47200,RCO_Down_Np_Se)]),
	('START','auto','if',[47,1,Cause_Deact,4,3,(47300,RCO_Up_Np_Se)]),
	('START','auto','if',[47,1,Cause_Deact,4,3,(47400,RCO_Down_Np_Se)]),
	('START','auto','if',[47,1,Cause_Deact,4,3,(47500,RCO_Up_Np_Se)]),
	('START','auto','if',[47,1,Cause_Deact,4,3,(47150,RCO_Up_Np_Se)]),
	# yaotiao with CTPTime -----------------------------------------------
	('START','auto','if',[58,1,Cause_Act,4,3,(45000,SCO_Off_Np_Se)]),
	('START','auto','if',[58,1,Cause_Act,4,3,(45100,SCO_On_Np_Se)]),
	('START','auto','if',[58,1,Cause_Act,4,3,(45200,SCO_Off_Np_Se)]),
	('START','auto','if',[58,1,Cause_Act,4,3,(45300,SCO_On_Np_Se)]),
	('START','auto','if',[58,1,Cause_Act,4,3,(45400,SCO_Off_Np_Se)]),
	('START','auto','if',[58,1,Cause_Act,4,3,(45500,SCO_On_Np_Se)]),
	('START','auto','if',[58,1,Cause_Act,4,3,(45150,SCO_On_Np_Se)]),
	('START','auto','if',[59,1,Cause_Deact,4,3,(46000,DCO_Off_Np_Se)]),
	('START','auto','if',[59,1,Cause_Deact,4,3,(46100,DCO_On_Np_Se)]),
	('START','auto','if',[59,1,Cause_Deact,4,3,(46200,DCO_Off_Np_Se)]),
	('START','auto','if',[59,1,Cause_Deact,4,3,(46300,DCO_On_Np_Se)]),
	('START','auto','if',[59,1,Cause_Deact,4,3,(46400,DCO_Off_Np_Se)]),
	('START','auto','if',[59,1,Cause_Deact,4,3,(46500,DCO_On_Np_Se)]),
	('START','auto','if',[59,1,Cause_Deact,4,3,(46150,DCO_Off_Np_Se)]),
	('START','auto','if',[60,1,Cause_Deact,4,3,(47000,RCO_Down_Np_Se)]),
	('START','auto','if',[60,1,Cause_Deact,4,3,(47100,RCO_Up_Np_Se)]),
	('START','auto','if',[60,1,Cause_Deact,4,3,(47200,RCO_Down_Np_Se)]),
	('START','auto','if',[60,1,Cause_Deact,4,3,(47300,RCO_Up_Np_Se)]),
	('START','auto','if',[60,1,Cause_Deact,4,3,(47400,RCO_Down_Np_Se)]),
	('START','auto','if',[60,1,Cause_Deact,4,3,(47500,RCO_Up_Np_Se)]),
	('START','auto','if',[60,1,Cause_Deact,4,3,(47150,RCO_Up_Np_Se)]),
	# asdu 48: -100 - 0 --------------------------------------------------
	('START','auto','if',[48,1,Cause_Deact,4,3,(48150,-23,0x80)]),
	('START','auto','if',[48,1,Cause_Deact,4,3,(48000,-101,0x80)]),
	('START','auto','if',[48,1,Cause_Deact,4,3,(48000,-100,0x80)]),
	('START','auto','if',[48,1,Cause_Deact,4,3,(48050,-10,0x80)]),
	('START','auto','if',[48,1,Cause_Deact,4,3,(48100,0,0x80)]),
	('START','auto','if',[48,1,Cause_Deact,4,3,(48100,1,0x80)]),
	# asdu 48: 0 - 100
	('START','auto','if',[48,1,Cause_Deact,4,3,(48200,-1,0x80)]),
	('START','auto','if',[48,1,Cause_Deact,4,3,(48200,0,0x80)]),
	('START','auto','if',[48,1,Cause_Deact,4,3,(48250,10,0x80)]),
	('START','auto','if',[48,1,Cause_Deact,4,3,(48300,100,0x80)]),
	('START','auto','if',[48,1,Cause_Deact,4,3,(48300,101,0x80)]),
	# asdu 48: -100 - 100
	('START','auto','if',[48,1,Cause_Deact,4,3,(48400,-101,0x80)]),
	('START','auto','if',[48,1,Cause_Deact,4,3,(48400,-100,0x80)]),
	('START','auto','if',[48,1,Cause_Deact,4,3,(48450,-10,0x80)]),
	('START','auto','if',[48,1,Cause_Deact,4,3,(48450,10,0x80)]),
	('START','auto','if',[48,1,Cause_Deact,4,3,(48500,100,0x80)]),
	('START','auto','if',[48,1,Cause_Deact,4,3,(48500,101,0x80)]),
	# asdu 48: -32768 - -32767
	('START','auto','if',[48,1,Cause_Deact,4,3,(48600,-32768,0x80)]),
	('START','auto','if',[48,1,Cause_Deact,4,3,(48650,-32767,0x80)]),
	('START','auto','if',[48,1,Cause_Deact,4,3,(48700,-32766,0x80)]),
	# asdu 48:  32766 - 32767
	('START','auto','if',[48,1,Cause_Deact,4,3,(48800,32766,0x80)]),
	('START','auto','if',[48,1,Cause_Deact,4,3,(48850,32767,0x80)]),
	('START','auto','if',[48,1,Cause_Deact,4,3,(48900,32765,0x80)]),
	# asdu 61: -100 - 0 --------------------------------------------------
	('START','auto','if',[61,1,Cause_Deact,4,3,(48150,-23,0x80)]),
	('START','auto','if',[61,1,Cause_Deact,4,3,(48000,-101,0x80)]),
	('START','auto','if',[61,1,Cause_Deact,4,3,(48000,-100,0x80)]),
	('START','auto','if',[61,1,Cause_Deact,4,3,(48050,-10,0x80)]),
	('START','auto','if',[61,1,Cause_Deact,4,3,(48100,0,0x80)]),
	('START','auto','if',[61,1,Cause_Deact,4,3,(48100,1,0x80)]),
	# asdu 61: 0 - 100
	('START','auto','if',[61,1,Cause_Deact,4,3,(48200,-1,0x80)]),
	('START','auto','if',[61,1,Cause_Deact,4,3,(48200,0,0x80)]),
	('START','auto','if',[61,1,Cause_Deact,4,3,(48250,10,0x80)]),
	('START','auto','if',[61,1,Cause_Deact,4,3,(48300,100,0x80)]),
	('START','auto','if',[61,1,Cause_Deact,4,3,(48300,101,0x80)]),
	# asdu 61: -100 - 100
	('START','auto','if',[61,1,Cause_Deact,4,3,(48400,-101,0x80)]),
	('START','auto','if',[61,1,Cause_Deact,4,3,(48400,-100,0x80)]),
	('START','auto','if',[61,1,Cause_Deact,4,3,(48450,-10,0x80)]),
	('START','auto','if',[61,1,Cause_Deact,4,3,(48450,10,0x80)]),
	('START','auto','if',[61,1,Cause_Deact,4,3,(48500,100,0x80)]),
	('START','auto','if',[61,1,Cause_Deact,4,3,(48500,101,0x80)]),
	# asdu 61: -32768 - -32767
	('START','auto','if',[61,1,Cause_Deact,4,3,(48600,-32768,0x80)]),
	('START','auto','if',[61,1,Cause_Deact,4,3,(48650,-32767,0x80)]),
	('START','auto','if',[61,1,Cause_Deact,4,3,(48700,-32766,0x80)]),
	# asdu 61:  32766 - 32767
	('START','auto','if',[61,1,Cause_Deact,4,3,(48800,32766,0x80)]),
	('START','auto','if',[61,1,Cause_Deact,4,3,(48850,32767,0x80)]),
	('START','auto','if',[61,1,Cause_Deact,4,3,(48900,32765,0x80)]),
	# asdu 49: -100 - 0   -----------------------------------------------
	('START','auto','if',[49,1,Cause_Deact,4,3,(49150,-23,0x80)]),
	('START','auto','if',[49,1,Cause_Deact,4,3,(49000,-101,0x80)]),
	('START','auto','if',[49,1,Cause_Deact,4,3,(49000,-100,0x80)]),
	('START','auto','if',[49,1,Cause_Deact,4,3,(49050,-10,0x80)]),
	('START','auto','if',[49,1,Cause_Deact,4,3,(49100,0,0x80)]),
	('START','auto','if',[49,1,Cause_Deact,4,3,(49100,1,0x80)]),
	# asdu 49: 0 - 100
	('START','auto','if',[49,1,Cause_Deact,4,3,(49200,-1,0x80)]),
	('START','auto','if',[49,1,Cause_Deact,4,3,(49200,0,0x80)]),
	('START','auto','if',[49,1,Cause_Deact,4,3,(49250,10,0x80)]),
	('START','auto','if',[49,1,Cause_Deact,4,3,(49300,100,0x80)]),
	('START','auto','if',[49,1,Cause_Deact,4,3,(49300,101,0x80)]),
	# asdu 49: -100 - 100
	('START','auto','if',[49,1,Cause_Deact,4,3,(49400,-101,0x80)]),
	('START','auto','if',[49,1,Cause_Deact,4,3,(49400,-100,0x80)]),
	('START','auto','if',[49,1,Cause_Deact,4,3,(49450,-10,0x80)]),
	('START','auto','if',[49,1,Cause_Deact,4,3,(49450,10,0x80)]),
	('START','auto','if',[49,1,Cause_Deact,4,3,(49500,100,0x80)]),
	('START','auto','if',[49,1,Cause_Deact,4,3,(49500,101,0x80)]),
	# asdu 49: -32768 - -32767
	('START','auto','if',[49,1,Cause_Deact,4,3,(49600,-32768,0x80)]),
	('START','auto','if',[49,1,Cause_Deact,4,3,(49650,-32767,0x80)]),
	('START','auto','if',[49,1,Cause_Deact,4,3,(49700,-32766,0x80)]),
	# asdu 49: 32766 - 32767
	('START','auto','if',[49,1,Cause_Deact,4,3,(49800,32766,0x80)]),
	('START','auto','if',[49,1,Cause_Deact,4,3,(49850,32767,0x80)]),
	('START','auto','if',[49,1,Cause_Deact,4,3,(49900,32765,0x80)]),
	# asdu 62: -100 - 0   -----------------------------------------------
	('START','auto','if',[62,1,Cause_Deact,4,3,(49150,-23,0x80)]),
	('START','auto','if',[62,1,Cause_Deact,4,3,(49000,-101,0x80)]),
	('START','auto','if',[62,1,Cause_Deact,4,3,(49000,-100,0x80)]),
	('START','auto','if',[62,1,Cause_Deact,4,3,(49050,-10,0x80)]),
	('START','auto','if',[62,1,Cause_Deact,4,3,(49100,0,0x80)]),
	('START','auto','if',[62,1,Cause_Deact,4,3,(49100,1,0x80)]),
	# asdu 62: 0 - 100
	('START','auto','if',[62,1,Cause_Deact,4,3,(49200,-1,0x80)]),
	('START','auto','if',[62,1,Cause_Deact,4,3,(49200,0,0x80)]),
	('START','auto','if',[62,1,Cause_Deact,4,3,(49250,10,0x80)]),
	('START','auto','if',[62,1,Cause_Deact,4,3,(49300,100,0x80)]),
	('START','auto','if',[62,1,Cause_Deact,4,3,(49300,101,0x80)]),
	# asdu 62: -100 - 100
	('START','auto','if',[62,1,Cause_Deact,4,3,(49400,-101,0x80)]),
	('START','auto','if',[62,1,Cause_Deact,4,3,(49400,-100,0x80)]),
	('START','auto','if',[62,1,Cause_Deact,4,3,(49450,-10,0x80)]),
	('START','auto','if',[62,1,Cause_Deact,4,3,(49450,10,0x80)]),
	('START','auto','if',[62,1,Cause_Deact,4,3,(49500,100,0x80)]),
	('START','auto','if',[62,1,Cause_Deact,4,3,(49500,101,0x80)]),
	# asdu 62: -32768 - -32767
	('START','auto','if',[62,1,Cause_Deact,4,3,(49600,-32768,0x80)]),
	('START','auto','if',[62,1,Cause_Deact,4,3,(49650,-32767,0x80)]),
	('START','auto','if',[62,1,Cause_Deact,4,3,(49700,-32766,0x80)]),
	# asdu 62: 32766 - 32767
	('START','auto','if',[62,1,Cause_Deact,4,3,(49800,32766,0x80)]),
	('START','auto','if',[62,1,Cause_Deact,4,3,(49850,32767,0x80)]),
	('START','auto','if',[62,1,Cause_Deact,4,3,(49900,32765,0x80)]),
	# asdu 50: -3.141 - 0 ----------------------------------------------------------------
	('START','auto','if',[50,1,Cause_Deact,4,3,(50150,0,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50000,-3.142,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50000,-3.141,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50050,-1.141,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50100,-0.001,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50100,0,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50100,0.000001,0x80)]),
	# asdu 50: 0 - 3.141
	('START','auto','if',[50,1,Cause_Deact,4,3,(50200,-0.001,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50200,0,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50250,0.001,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50300,1.141,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50300,3.141,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50300,3.142,0x80)]),
	# asdu 50: -3.141 - 3.141
	('START','auto','if',[50,1,Cause_Deact,4,3,(50400,-3.142,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50400,-3.141,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50450,-1.141,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50450,0,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50450,1.141,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50500,3.141,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50500,3.142,0x80)]),
	# asdu 50: 3.40281e+38 - 3.40282e+38
	('START','auto','if',[50,1,Cause_Deact,4,3,(50650,3402800000000000,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50650,340280000000000000000000000000000000000,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50600,340281000000000000000000000000000000000,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50700,340282000000000000000000000000000000000,0x80)]),
	# asdu 50: -3.40282e+38 - -3.40281e+38
	('START','auto','if',[50,1,Cause_Deact,4,3,(50850,-3402800000000000,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50850,-340280000000000000000000000000000000000,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50800,-340281000000000000000000000000000000000,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50900,-340282000000000000000000000000000000000,0x80)]),
	# asdu 50: 340282.11 - 340282.22
	('START','auto','if',[50,1,Cause_Deact,4,3,(50910,340282.10,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50910,340282.11,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50915,340282.12,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50915,340282.2,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50915,340282.21,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50920,340282.22,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50920,340282.23,0x80)]),
	# asdu 50: 10000 - 20000
	('START','auto','if',[50,1,Cause_Deact,4,3,(50930,9999.999,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50930,10000,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50935,10000.001,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50935,15000.0001,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50935,19999.999,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50940,20000,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(50940,20000.001,0x80)]),
	# asdu 63: -3.141 - 0 ----------------------------------------------------------------
	('START','auto','if',[63,1,Cause_Deact,4,3,(50150,0,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50000,-3.142,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50000,-3.141,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50050,-1.141,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50100,-0.001,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50100,0,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50100,0.001,0x80)]),
	# asdu 63: 0 - 3.141
	('START','auto','if',[63,1,Cause_Deact,4,3,(50200,-0.001,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50200,0,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50250,0.001,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50300,1.141,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50300,3.141,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50300,3.142,0x80)]),
	# asdu 63: -3.141 - 3.141
	('START','auto','if',[63,1,Cause_Deact,4,3,(50400,-3.142,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50400,-3.141,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50450,-1.141,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50450,0,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50450,1.141,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50500,3.141,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50500,3.142,0x80)]),
	# asdu 63: 3.40281e+38 - 3.40282e+38
	('START','auto','if',[63,1,Cause_Deact,4,3,(50650,3402800000000000,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50650,340280000000000000000000000000000000000,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50600,340281000000000000000000000000000000000,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50700,340282000000000000000000000000000000000,0x80)]),
	# asdu 63: -3.40282e+38 - -3.40281e+38
	('START','auto','if',[63,1,Cause_Deact,4,3,(50850,-3402800000000000,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50850,-340280000000000000000000000000000000000,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50800,-340281000000000000000000000000000000000,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50900,-340282000000000000000000000000000000000,0x80)]),
	# asdu 63: 340282.11 - 340282.22
	('START','auto','if',[63,1,Cause_Deact,4,3,(50910,340282.10,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50910,340282.11,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50915,340282.12,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50915,340282.2,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50915,340282.21,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50920,340282.22,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50920,340282.23,0x80)]),
	# asdu 63: 10000 - 20000
	('START','auto','if',[63,1,Cause_Deact,4,3,(50930,9999.999,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50930,10000,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50935,10000.001,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50935,15000.0001,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50935,19999.999,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50940,20000,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(50940,20000.001,0x80)]),
	# asdu 51: 0 - 20000 --------------------------------------------------------------
	# asdu 64: 0 - 20000 --------------------------------------------------------------
	# yaokong addr:16777214 - 16777215  value 1, 1--------------------------------------
	('START','auto','if',[45,1,Cause_Act,4,3,(16777213,SCO_On_Np_Se)]),
	('START','auto','if',[45,1,Cause_Act,4,3,(16777214,SCO_On_Np_Se)]),
	('START','auto','if',[45,1,Cause_Act,4,3,(16777215,SCO_On_Np_Se)]),
	('START','auto','if',[46,1,Cause_Deact,4,3,(16777213,DCO_On_Np_Se)]),
	('START','auto','if',[46,1,Cause_Deact,4,3,(16777214,DCO_On_Np_Se)]),
	('START','auto','if',[46,1,Cause_Deact,4,3,(16777215,DCO_On_Np_Se)]),
	('START','auto','if',[47,1,Cause_Deact,4,3,(16777213,RCO_Up_Np_Se)]),
	('START','auto','if',[47,1,Cause_Deact,4,3,(16777214,RCO_Up_Np_Se)]),
	('START','auto','if',[47,1,Cause_Deact,4,3,(16777215,RCO_Up_Np_Se)]),
	('START','auto','if',[58,1,Cause_Act,4,3,(16777213,SCO_On_Np_Se)]),
	('START','auto','if',[58,1,Cause_Act,4,3,(16777214,SCO_On_Np_Se)]),
	('START','auto','if',[58,1,Cause_Act,4,3,(16777215,SCO_On_Np_Se)]),
	('START','auto','if',[59,1,Cause_Deact,4,3,(16777213,DCO_On_Np_Se)]),
	('START','auto','if',[59,1,Cause_Deact,4,3,(16777214,DCO_On_Np_Se)]),
	('START','auto','if',[59,1,Cause_Deact,4,3,(16777215,DCO_On_Np_Se)]),
	('START','auto','if',[60,1,Cause_Deact,4,3,(16777213,RCO_Up_Np_Se)]),
	('START','auto','if',[60,1,Cause_Deact,4,3,(16777214,RCO_Up_Np_Se)]),
	('START','auto','if',[60,1,Cause_Deact,4,3,(16777215,RCO_Up_Np_Se)]),
	# yaotiao addr:16777214 - 16777215  value -10 - 10 --------------------------------------
	('START','auto','if',[48,1,Cause_Deact,4,3,(16777213,0,0x80)]),
	('START','auto','if',[48,1,Cause_Deact,4,3,(16777214,0,0x80)]),
	('START','auto','if',[48,1,Cause_Deact,4,3,(16777215,0,0x80)]),
	('START','auto','if',[49,1,Cause_Deact,4,3,(16777213,0,0x80)]),
	('START','auto','if',[49,1,Cause_Deact,4,3,(16777214,0,0x80)]),
	('START','auto','if',[49,1,Cause_Deact,4,3,(16777215,0,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(16777213,0,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(16777214,0,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,3,(16777215,0,0x80)]),
	('START','auto','if',[61,1,Cause_Deact,4,3,(16777213,0,0x80)]),
	('START','auto','if',[61,1,Cause_Deact,4,3,(16777214,0,0x80)]),
	('START','auto','if',[61,1,Cause_Deact,4,3,(16777215,0,0x80)]),
	('START','auto','if',[62,1,Cause_Deact,4,3,(16777213,0,0x80)]),
	('START','auto','if',[62,1,Cause_Deact,4,3,(16777214,0,0x80)]),
	('START','auto','if',[62,1,Cause_Deact,4,3,(16777215,0,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(16777213,0,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(16777214,0,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,3,(16777215,0,0x80)]),
	# yaomai
	('START','auto','if',[101,1,Cause_Deact,4,3,(0,0x05)]),
	('START','auto','if',[101,1,Cause_Deact,4,3,(0,0x05)]),
	('START','auto','if',[101,1,Cause_Deact,4,3,(0,0x05)]),
	# clock syn
	('START','auto','if',[103,1,Cause_Deact,4,3,(0,0x05)]),
	('START','auto','if',[103,1,Cause_Deact,4,3,(0,0x05)]),
	('START','auto','if',[103,1,Cause_Deact,4,3,(0,0x05)]),
	# wrong device id=4
	('START','auto','if',[45,1,Cause_Act,4,4,(2100,SCO_On_Np_Se)]),
	('START','auto','if',[46,1,Cause_Deact,4,4,(2100,DCO_On_Np_Se)]),
	('START','auto','if',[47,1,Cause_Deact,4,4,(2100,RCO_Up_Np_Se)]),
	('START','auto','if',[48,1,Cause_Deact,4,4,(3650,-23,0x80)]),
	('START','auto','if',[49,1,Cause_Deact,4,4,(3650,-23,0x80)]),
	('START','auto','if',[50,1,Cause_Deact,4,4,(3650,-3.3,0x80)]),
	('START','auto','if',[58,1,Cause_Act,4,4,(2100,SCO_On_Np_Se)]),
	('START','auto','if',[59,1,Cause_Deact,4,4,(2100,DCO_On_Np_Se)]),
	('START','auto','if',[60,1,Cause_Deact,4,4,(2100,RCO_Up_Np_Se)]),
	('START','auto','if',[61,1,Cause_Deact,4,4,(3650,-23,0x80)]),
	('START','auto','if',[62,1,Cause_Deact,4,4,(3650,-23,0x80)]),
	('START','auto','if',[63,1,Cause_Deact,4,4,(3650,-3.3,0x80)]),
	('START','auto','if',[101,1,Cause_Deact,4,4,(0,0x05)]),
	('START','auto','if',[103,1,Cause_Deact,4,4,(0,0x05)]),
	# s frame
	('START','auto','sf'),
	('START','auto','sf'),
	('START','auto','sf'),
	('START','auto','sf'),
	('START','auto','sf'),
	('START','auto','sf'),
	# u frame
	('START','auto','uf',STARTDT_ACT),
	('START','auto','uf',STARTDT_CON),
	('START','auto','uf',STOPDT_ACT),
	('START','auto','uf',STOPDT_CON),
	('START','auto','uf',TESTFR_ACT),
	('START','auto','uf',TESTFR_CON),
	('START','auto','uf',STARTDT_ACT),
	('START','auto','uf',STARTDT_CON),
	('START','auto','uf',STOPDT_ACT),
	('START','auto','uf',STOPDT_CON),
	('START','auto','uf',TESTFR_ACT),
	('START','auto','uf',TESTFR_CON),
]