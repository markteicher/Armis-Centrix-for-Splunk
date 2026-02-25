## Time Zone Values Used in Tenable VM Exclusions

### America/Chicago

Exclusion schedule runs in Central Time  
UTC-6 / UTC-5 (DST aware)

---

### America/New_York

Exclusion schedule runs in Eastern Time  
UTC-5 / UTC-4 (DST aware)

---

### US/Eastern

Alias of America/New_York  
Same behavior. Different string.

---

## Why This Is Operationally Important

If an exclusion says:

Start: 02:00  
End: 04:00  

That window executes relative to the configured timezone.

If one exclusion is America/New_York  
and another is America/Chicago,  

the window fires one hour apart.

If it’s blank (☠ Not Set):

Behavior depends on how Tenable processes it:

- May default to system timezone  
- May default to UTC  
- May fail validation  
- May cause schedule drift  
