# Task: data sensitivity

Classify the data this system handles and identify where it is exposed.

Fields whose *names* suggest sensitivity — credentials, PII, financial, health —
are supplied to you already. Your job is the two things name-matching cannot do:

1. **Fields that are sensitive without looking it are.** A `notes` column
   holding support-ticket bodies, a `metadata` blob carrying identifiers, a
   `description` free-text field users paste account numbers into. These carry
   real data and no scanner will ever flag them.
2. **Where sensitive data actually goes.** For each sensitive field, which
   endpoints return it, which log statements record it, which exports and
   third-party calls include it. A field that is never exposed is a much smaller
   problem than one serialized into every API response by a default serializer.

Look specifically at serializers, `to_dict`/`__repr__` implementations, log
statements in error paths, and any generic "return the whole object" pattern.
Sensitive data reaches logs through exception handlers more often than through
deliberate logging.

For each field record: name, classification, where it lives, and which channels
expose it.
