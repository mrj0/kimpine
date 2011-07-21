# Copyright 2008 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""URL mappings for the codereview package."""

# NOTE: Must import *, since Django looks for things here, e.g. handler500.
from django.conf.urls.defaults import *
import django.views.defaults
from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
import settings

admin.autodiscover()

from codereview import feeds

urlpatterns = patterns(
    'codereview.views',
    (r'^$', 'index'),
    (r'^all$', 'all'),
    (r'^mine$', 'mine'),
    (r'^starred$', 'starred'),
    (r'^new$', 'new'),
    (r'^upload$', 'upload'),
    url(r'^(?P<issue_id>\d+)$', 'show', name='show_bare_issue_number'),
    (r'^(?P<issue_id>\d+)/(show)?$', 'show'),
    (r'^(?P<issue_id>\d+)/add$', 'add'),
    (r'^(?P<issue_id>\d+)/edit$', 'edit'),
    (r'^(?P<issue_id>\d+)/delete$', 'delete'),
    (r'^(?P<issue_id>\d+)/close$', 'close'),
    (r'^(?P<issue_id>\d+)/mail$', 'mailissue'),
    (r'^(?P<issue_id>\d+)/publish$', 'publish'),
    (r'^download/issue(?P<issue_id>\d+)_(?P<patchset_id>\d+)\.diff', 'download'),
    (r'^download/issue(?P<issue_id>\d+)_(?P<patchset_id>\d+)_(?P<patch_id>\d+)\.diff', 'download_patch'),
    (r'^(?P<issue_id>\d+)/patch/(?P<patchset_id>\d+)/(?P<patch_id>\d+)$', 'patch'),
    (r'^(?P<issue_id>\d+)/image/(?P<patchset_id>\d+)/(?P<patch_id>\d+)/(?P<image_type>\d+)$', 'image'),
    (r'^(?P<issue_id>\d+)/diff/(?P<patchset_id>\d+)/(?P<patch_filename>.+)$', 'diff'),
    (r'^(?P<issue_id>\d+)/diff2/(?P<ps_left_id>\d+):(?P<ps_right_id>\d+)/(?P<patch_filename>.+)$', 'diff2'),
    (r'^(?P<issue_id>\d+)/diff_skipped_lines/(?P<patchset_id>\d+)/(?P<patch_id>\d+)/(?P<id_before>\d+)/'
        r'(?P<id_after>\d+)/(?P<where>[tba])/(?P<column_width>\d+)$',
     'diff_skipped_lines'),
    url(r'^(?P<issue_id>\d+)/diff_skipped_lines/(?P<patchset_id>\d+)/(?P<patch_id>\d+)/$',
     django.views.defaults.page_not_found, name='diff_skipped_lines_prefix'),
    (r'^(?P<issue_id>\d+)/diff2_skipped_lines/(?P<ps_left_id>\d+):(?P<ps_right_id>\d+)/(?P<patch_id>\d+)/'
        r'(?P<id_before>\d+)/(?P<id_after>\d+)/(?P<where>[tba])/(?P<column_width>\d+)$',
     'diff2_skipped_lines'),
    url(r'^(?P<issue_id>\d+)/diff2_skipped_lines/(?P<ps_left_id>\d+):(?P<ps_right_id>\d+)/(?P<column_width>\d+)/$',
     django.views.defaults.page_not_found, name='diff2_skipped_lines_prefix'),
    (r'^(?P<issue_id>\d+)/upload_content/(?P<patchset_id>\d+)/(?P<patch_id>\d+)$', 'upload_content'),
    (r'^(?P<issue_id>\d+)/upload_patch/(?P<patchset_id>\d+)$', 'upload_patch'),
    (r'^(?P<issue_id>\d+)/description$', 'description'),
    (r'^(?P<issue_id>\d+)/fields', 'fields'),
    (r'^(?P<issue_id>\d+)/star$', 'star'),
    (r'^(?P<issue_id>\d+)/unstar$', 'unstar'),
    (r'^(?P<issue_id>\d+)/draft_message$', 'draft_message'),
    (r'^api/(?P<issue_id>\d+)/?$', 'api_issue'),
    (r'^api/(?P<issue_id>\d+)/(?P<patchset_id>\d+)/?$', 'api_patchset'),
    (r'^user/(?P<user_key>.+)$', 'show_user'),
    (r'^inline_draft$', 'inline_draft'),
    (r'^settings$', 'settings'),
    (r'^account_delete$', 'account_delete'),
    (r'^user_popup/(?P<user_key>.+)$', 'user_popup'),
    (r'^(?P<issue_id>\d+)/patchset/(?P<patchset_id>\d+)$', 'patchset'),
    (r'^(?P<issue_id>\d+)/patchset/(?P<patchset_id>\d+)/delete$', 'delete_patchset'),
    (r'^account$', 'account'),
    (r'^use_uploadpy$', 'use_uploadpy'),
    (r'^xsrf_token$', 'xsrf_token'),
    # patching upload.py on the fly
    (r'^dynamic/upload.py$', 'customized_upload_py'),
    (r'^search$', 'search'),
    )

feed_dict = {
  'reviews': feeds.ReviewsFeed,
  'closed': feeds.ClosedFeed,
  'mine' : feeds.MineFeed,
  'all': feeds.AllFeed,
  'issue' : feeds.OneIssueFeed,
}

urlpatterns += patterns(
    '',
    (r'^accounts/login/$', 'django.contrib.auth.views.login'),
    (r'^accounts/logout/$', 'django.contrib.auth.views.logout_then_login'),
    (r'^accounts/change_password/$', 'django.contrib.auth.views.password_change',
      {'post_change_redirect': '/'}),
    ('^admin/', include(admin.site.urls)),
    (r'^rss/(?P<url>.*)$', 'django.contrib.syndication.views.feed',
     {'feed_dict': feed_dict}),
    )

if settings.DEBUG:
  urlpatterns += staticfiles_urlpatterns()
