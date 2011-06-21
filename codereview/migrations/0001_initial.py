# encoding: utf-8
import datetime
from south.db import db
from south.v2 import SchemaMigration
from django.db import models

class Migration(SchemaMigration):

    def forwards(self, orm):
        
        # Adding model 'Issue'
        db.create_table('codereview_issue', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('subject', self.gf('django.db.models.fields.CharField')(max_length=100)),
            ('description', self.gf('django.db.models.fields.TextField')(default='', blank=True)),
            ('owner', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User'])),
            ('created', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, blank=True)),
            ('modified', self.gf('django.db.models.fields.DateTimeField')(auto_now=True, blank=True)),
            ('reviewers', self.gf('codereview.models.MultiEmailField')(default=[], blank=True)),
            ('cc', self.gf('codereview.models.MultiEmailField')(default=[], blank=True)),
            ('closed', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('private', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('n_comments', self.gf('django.db.models.fields.IntegerField')()),
        ))
        db.send_create_signal('codereview', ['Issue'])

        # Adding model 'PatchSet'
        db.create_table('codereview_patchset', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('issue', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['codereview.Issue'])),
            ('message', self.gf('django.db.models.fields.CharField')(default='', max_length=500)),
            ('data', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('created', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, blank=True)),
            ('modified', self.gf('django.db.models.fields.DateTimeField')(auto_now=True, blank=True)),
            ('n_comments', self.gf('django.db.models.fields.IntegerField')(default=0)),
        ))
        db.send_create_signal('codereview', ['PatchSet'])

        # Adding model 'Message'
        db.create_table('codereview_message', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('issue', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['codereview.Issue'])),
            ('subject', self.gf('django.db.models.fields.CharField')(default='', max_length=100)),
            ('sender', self.gf('django.db.models.fields.EmailField')(max_length=75)),
            ('recipients', self.gf('codereview.models.MultiEmailField')()),
            ('date', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, blank=True)),
            ('text', self.gf('django.db.models.fields.TextField')()),
            ('draft', self.gf('django.db.models.fields.BooleanField')(default=False)),
        ))
        db.send_create_signal('codereview', ['Message'])

        # Adding model 'Content'
        db.create_table('codereview_content', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('text', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('data', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('checksum', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('is_uploaded', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('is_bad', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('file_too_large', self.gf('django.db.models.fields.BooleanField')(default=False)),
        ))
        db.send_create_signal('codereview', ['Content'])

        # Adding model 'Patch'
        db.create_table('codereview_patch', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('patchset', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['codereview.PatchSet'])),
            ('filename', self.gf('django.db.models.fields.CharField')(max_length=500)),
            ('status', self.gf('django.db.models.fields.CharField')(max_length=100, null=True, blank=True)),
            ('text', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
            ('content', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['codereview.Content'], null=True, blank=True)),
            ('patched_content', self.gf('django.db.models.fields.related.ForeignKey')(blank=True, related_name='patch2_set', null=True, to=orm['codereview.Content'])),
            ('is_binary', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('delta', self.gf('codereview.models.MultiForeignKeyField')(null=True, blank=True)),
            ('delta_calculated', self.gf('django.db.models.fields.BooleanField')(default=False)),
        ))
        db.send_create_signal('codereview', ['Patch'])

        # Adding model 'Comment'
        db.create_table('codereview_comment', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('patch', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['codereview.Patch'])),
            ('author', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User'])),
            ('date', self.gf('django.db.models.fields.DateTimeField')(auto_now=True, blank=True)),
            ('lineno', self.gf('django.db.models.fields.IntegerField')()),
            ('text', self.gf('django.db.models.fields.TextField')()),
            ('left', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('draft', self.gf('django.db.models.fields.BooleanField')(default=True)),
        ))
        db.send_create_signal('codereview', ['Comment'])

        # Adding model 'Account'
        db.create_table('codereview_account', (
            ('id', self.gf('django.db.models.fields.AutoField')(primary_key=True)),
            ('user', self.gf('django.db.models.fields.related.ForeignKey')(to=orm['auth.User'])),
            ('email', self.gf('django.db.models.fields.EmailField')(max_length=75)),
            ('nickname', self.gf('django.db.models.fields.CharField')(max_length=50)),
            ('default_context', self.gf('django.db.models.fields.IntegerField')(default=10)),
            ('default_column_width', self.gf('django.db.models.fields.IntegerField')(default=80)),
            ('created', self.gf('django.db.models.fields.DateTimeField')(auto_now_add=True, blank=True)),
            ('modified', self.gf('django.db.models.fields.DateTimeField')(auto_now=True, blank=True)),
            ('stars', self.gf('codereview.models.MultiForeignKeyField')()),
            ('fresh', self.gf('django.db.models.fields.BooleanField')(default=False)),
            ('uploadpy_hint', self.gf('django.db.models.fields.BooleanField')(default=True)),
            ('notify_by_email', self.gf('django.db.models.fields.BooleanField')(default=True)),
            ('xsrf_secret', self.gf('django.db.models.fields.TextField')(null=True, blank=True)),
        ))
        db.send_create_signal('codereview', ['Account'])


    def backwards(self, orm):
        
        # Deleting model 'Issue'
        db.delete_table('codereview_issue')

        # Deleting model 'PatchSet'
        db.delete_table('codereview_patchset')

        # Deleting model 'Message'
        db.delete_table('codereview_message')

        # Deleting model 'Content'
        db.delete_table('codereview_content')

        # Deleting model 'Patch'
        db.delete_table('codereview_patch')

        # Deleting model 'Comment'
        db.delete_table('codereview_comment')

        # Deleting model 'Account'
        db.delete_table('codereview_account')


    models = {
        'auth.group': {
            'Meta': {'object_name': 'Group'},
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '80'}),
            'permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'})
        },
        'auth.permission': {
            'Meta': {'ordering': "('content_type__app_label', 'content_type__model', 'codename')", 'unique_together': "(('content_type', 'codename'),)", 'object_name': 'Permission'},
            'codename': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'content_type': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['contenttypes.ContentType']"}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '50'})
        },
        'auth.user': {
            'Meta': {'object_name': 'User'},
            'date_joined': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75', 'blank': 'True'}),
            'first_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'groups': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Group']", 'symmetrical': 'False', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_active': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'is_staff': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'is_superuser': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'last_login': ('django.db.models.fields.DateTimeField', [], {'default': 'datetime.datetime.now'}),
            'last_name': ('django.db.models.fields.CharField', [], {'max_length': '30', 'blank': 'True'}),
            'password': ('django.db.models.fields.CharField', [], {'max_length': '128'}),
            'user_permissions': ('django.db.models.fields.related.ManyToManyField', [], {'to': "orm['auth.Permission']", 'symmetrical': 'False', 'blank': 'True'}),
            'username': ('django.db.models.fields.CharField', [], {'unique': 'True', 'max_length': '30'})
        },
        'codereview.account': {
            'Meta': {'object_name': 'Account'},
            'created': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'default_column_width': ('django.db.models.fields.IntegerField', [], {'default': '80'}),
            'default_context': ('django.db.models.fields.IntegerField', [], {'default': '10'}),
            'email': ('django.db.models.fields.EmailField', [], {'max_length': '75'}),
            'fresh': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'modified': ('django.db.models.fields.DateTimeField', [], {'auto_now': 'True', 'blank': 'True'}),
            'nickname': ('django.db.models.fields.CharField', [], {'max_length': '50'}),
            'notify_by_email': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'stars': ('codereview.models.MultiForeignKeyField', [], {}),
            'uploadpy_hint': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'user': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.User']"}),
            'xsrf_secret': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'})
        },
        'codereview.comment': {
            'Meta': {'object_name': 'Comment'},
            'author': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.User']"}),
            'date': ('django.db.models.fields.DateTimeField', [], {'auto_now': 'True', 'blank': 'True'}),
            'draft': ('django.db.models.fields.BooleanField', [], {'default': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'left': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'lineno': ('django.db.models.fields.IntegerField', [], {}),
            'patch': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['codereview.Patch']"}),
            'text': ('django.db.models.fields.TextField', [], {})
        },
        'codereview.content': {
            'Meta': {'object_name': 'Content'},
            'checksum': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'data': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'file_too_large': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_bad': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'is_uploaded': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'text': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'})
        },
        'codereview.issue': {
            'Meta': {'object_name': 'Issue'},
            'cc': ('codereview.models.MultiEmailField', [], {'default': '[]', 'blank': 'True'}),
            'closed': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'created': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'description': ('django.db.models.fields.TextField', [], {'default': "''", 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'modified': ('django.db.models.fields.DateTimeField', [], {'auto_now': 'True', 'blank': 'True'}),
            'n_comments': ('django.db.models.fields.IntegerField', [], {}),
            'owner': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['auth.User']"}),
            'private': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'reviewers': ('codereview.models.MultiEmailField', [], {'default': '[]', 'blank': 'True'}),
            'subject': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        },
        'codereview.message': {
            'Meta': {'object_name': 'Message'},
            'date': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'draft': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'issue': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['codereview.Issue']"}),
            'recipients': ('codereview.models.MultiEmailField', [], {}),
            'sender': ('django.db.models.fields.EmailField', [], {'max_length': '75'}),
            'subject': ('django.db.models.fields.CharField', [], {'default': "''", 'max_length': '100'}),
            'text': ('django.db.models.fields.TextField', [], {})
        },
        'codereview.patch': {
            'Meta': {'object_name': 'Patch'},
            'content': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['codereview.Content']", 'null': 'True', 'blank': 'True'}),
            'delta': ('codereview.models.MultiForeignKeyField', [], {'null': 'True', 'blank': 'True'}),
            'delta_calculated': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'filename': ('django.db.models.fields.CharField', [], {'max_length': '500'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'is_binary': ('django.db.models.fields.BooleanField', [], {'default': 'False'}),
            'patched_content': ('django.db.models.fields.related.ForeignKey', [], {'blank': 'True', 'related_name': "'patch2_set'", 'null': 'True', 'to': "orm['codereview.Content']"}),
            'patchset': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['codereview.PatchSet']"}),
            'status': ('django.db.models.fields.CharField', [], {'max_length': '100', 'null': 'True', 'blank': 'True'}),
            'text': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'})
        },
        'codereview.patchset': {
            'Meta': {'object_name': 'PatchSet'},
            'created': ('django.db.models.fields.DateTimeField', [], {'auto_now_add': 'True', 'blank': 'True'}),
            'data': ('django.db.models.fields.TextField', [], {'null': 'True', 'blank': 'True'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'issue': ('django.db.models.fields.related.ForeignKey', [], {'to': "orm['codereview.Issue']"}),
            'message': ('django.db.models.fields.CharField', [], {'default': "''", 'max_length': '500'}),
            'modified': ('django.db.models.fields.DateTimeField', [], {'auto_now': 'True', 'blank': 'True'}),
            'n_comments': ('django.db.models.fields.IntegerField', [], {'default': '0'})
        },
        'contenttypes.contenttype': {
            'Meta': {'ordering': "('name',)", 'unique_together': "(('app_label', 'model'),)", 'object_name': 'ContentType', 'db_table': "'django_content_type'"},
            'app_label': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'id': ('django.db.models.fields.AutoField', [], {'primary_key': 'True'}),
            'model': ('django.db.models.fields.CharField', [], {'max_length': '100'}),
            'name': ('django.db.models.fields.CharField', [], {'max_length': '100'})
        }
    }

    complete_apps = ['codereview']
