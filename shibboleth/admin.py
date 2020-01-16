from __future__ import absolute_import, division, print_function, unicode_literals

from django.contrib import admin

from . import models

@admin.register(models.GroupMapping)
class GroupMappingAdmin(admin.ModelAdmin):
    list_display = ('group', 'attr_value')
    list_editable = ('attr_value',)

