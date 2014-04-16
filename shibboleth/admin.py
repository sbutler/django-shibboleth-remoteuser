from django.contrib import admin

from shibboleth import models

class GroupMappingAdmin(admin.ModelAdmin):
    list_display = ('group', 'attr_value')
    list_editable = ('attr_value',)

admin.site.register(models.GroupMapping, GroupMappingAdmin)

