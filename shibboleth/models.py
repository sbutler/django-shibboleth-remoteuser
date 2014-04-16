from django.contrib.auth.models import Group
from django.db import models

ATTR_VALUE_MAX_LENGTH = 255

class GroupMapping(models.Model):
    """ Mapping between a Django group object and the shibboleth attribute value. """

    group = models.ForeignKey(Group)
    attr_value = models.CharField(max_length=ATTR_VALUE_MAX_LENGTH, verbose_name='attribute value')

    def __unicode__(self):
        return self.group.name

