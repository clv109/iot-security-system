AUTHORIZED_NAMES = [
  "Jane_Doe", 
 "Bob"
]
# These currently are placeholder names, replace them with the real personal identifiers intended to be used

DEFAULT_MAX_DURATION = 5
#default duration value (5 minutes) of time users are allowed to stay due to lack of data and newly implemented column on SQLite database


# Quiet hours
QUIET_HOURS_START = 21
QUIET_HOURS_END = 6


NEW_USER_GRACE_THRESHOLD = 5
#set a baseline of 5 detections (frequency)  for new users with limited historical data
