from django.db import models

#A quickScan object is a 'scan'
class quickScan(models.Model):
    scan_id = models.AutoField(primary_key=True)        #Not the UUID, this ID is for DB only
    scan_uuid = models.CharField(max_length=40)
    scan_date = models.DateTimeField(editable=False)
    scan_url = models.URLField(max_length=200)
    scan_status = models.CharField(max_length=7)
    scan_results = models.TextField(max_length=5000, default="")    #max_length must be large enough to hold all data returned in headers, cookies, etc.
    