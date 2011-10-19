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

"""App Engine data model (schema) definition for Rietveld."""

# Python imports
import logging
import os
import re
import time
import base64
from collections import namedtuple
from hashlib import md5

# Local imports
import engine
import patching

# Django imports
from django.core.cache import cache
from django.db import models
from django.contrib.auth.models import User
from django.db.models import Q

# South imports
from south.modelsinspector import add_introspection_rules

# Pygment imports
from pygments import highlight
from pygments.lexers import get_lexer_for_filename, TextLexer
from pygments.formatters import HtmlFormatter
from pygments.util import ClassNotFound


CONTEXT_CHOICES = (3, 10, 25, 50, 75, 100)

### Custom Fields

class MultiEmailField(models.TextField):

  __metaclass__ = models.SubfieldBase

  def get_prep_value(self, value):
    if value is None:
      return value
    return ','.join(value)

  def to_python(self, value):
    if type(value) == list:
      return value
    if value is None:
      return value
    if value == '':
      return []
    return value.split(',')

add_introspection_rules([], ["^codereview\.models\.MultiEmailField"])

### Issues, PatchSets, Patches, Contents, Comments, Messages ###


class Issue(models.Model):
  """The major top-level entity.

  It has one or more PatchSets as its descendants.
  """

  subject = models.CharField(max_length=100)
  description = models.TextField(blank=True, default='')
  owner = models.ForeignKey(User)
  created = models.DateTimeField(auto_now_add=True)
  modified = models.DateTimeField(auto_now=True)
  reviewers = MultiEmailField(blank=True, default=[])
  cc = MultiEmailField(blank=True, default=[])
  closed = models.BooleanField(default=False)
  private = models.BooleanField(default=False)
  n_comments = models.IntegerField()

  _is_starred = None

  def is_starred(self, user):
    """Whether the current user has this issue starred."""
    if self._is_starred is not None:
      return self._is_starred
    if user.is_anonymous():
      self._is_starred = False
    else:
      try:
        account = Account.objects.get(user=user)
        self._is_starred = self in account.stars.all()
      except Account.DoesNotExist:
        self._is_starred = False
    return self._is_starred

  def user_can_edit(self, user):
    """Return true if the given user has permission to edit this issue."""
    return user == self.owner or user.is_superuser

  def update_comment_count(self, n):
    """Increment the n_comments property by n.

    If n_comments in None, compute the count through a query.  (This
    is a transitional strategy while the database contains Issues
    created using a previous version of the schema.)
    """
    if self.n_comments is None:
      self.n_comments = self._get_num_comments()
    self.n_comments += n

  @property
  def num_comments(self):
    """The number of non-draft comments for this issue.

    This is almost an alias for self.n_comments, except that if
    n_comments is None, it is computed through a query, and stored,
    using n_comments as a cache.
    """
    if self.n_comments is None:
      self.n_comments = self._get_num_comments()
    return self.n_comments

  def _get_num_comments(self):
    """Helper to compute the number of comments through a query."""
    return Comment.objects.filter(patch__patchset__issue=self,
                                  draft=False).count()

  _num_drafts = None

  def num_drafts(self, user):
    """The number of draft comments on this issue for the current user.

    The value is expensive to compute, so it is cached.
    """
    if self._num_drafts is None:
      if user.is_anonymous():
        account = None
      else:
        try:
          account = Account.objects.get(user=user)
        except Account.DoesNotExist:
          account = None
      if account is None:
        self._num_drafts = 0
      else:
        query = Comment.objects.filter(patch__patchset__issue=self,
                                       author=account.user,
                                       draft=True)
        self._num_drafts = query.count()
    return self._num_drafts


class PatchSet(models.Model):
  """A set of patchset uploaded together.

  This is a descendant of an Issue and has Patches as descendants.
  """

  issue = models.ForeignKey(Issue)
  message = models.CharField(max_length=500, default='')
  data = models.TextField(null=True, blank=True)
  created = models.DateTimeField(auto_now_add=True)
  modified = models.DateTimeField(auto_now=True)
  n_comments = models.IntegerField(default=0)

  def update_comment_count(self, n):
    """Increment the n_comments property by n."""
    self.n_comments = self.num_comments + n

  @property
  def num_comments(self):
    """The number of non-draft comments for this issue.

    This is almost an alias for self.n_comments, except that if
    n_comments is None, 0 is returned.
    """
    # For older patchsets n_comments is None.
    return self.n_comments or 0


class Message(models.Model):
  """A copy of a message sent out in email.

  This is a descendant of an Issue.
  """

  issue = models.ForeignKey(Issue)
  subject = models.CharField(max_length=100, default='')
  sender = models.EmailField()
  recipients = MultiEmailField()
  date = models.DateTimeField(auto_now_add=True)
  text = models.TextField()
  draft = models.BooleanField(default=False)


  _approval = None

  @property
  def approval(self):
    """Is True when the message represents an approval of the review."""
    if self._approval is None:
      # Must contain 'lgtm' in a line that doesn't start with '>'.
      self._approval = any(
          True for line in self.text.lower().splitlines()
          if not line.strip().startswith('>') and 'lgtm' in line)
      # Must not be the issue owner
      self._approval &= self.issue.owner.email != self.sender
    return self._approval


class Content(models.Model):
  """The content of a text file.

  This is a descendant of a Patch.
  """

  # parent => Patch
  text = models.TextField(null=True, blank=True)
  # syntax highlighted text
  highlighted_text = models.TextField(null=True, blank=True)
  data = models.TextField(null=True, blank=True)
  # checksum over text/data depending on content type
  checksum = models.TextField(null=True, blank=True)
  is_uploaded = models.BooleanField(default=False)
  is_bad = models.BooleanField(default=False)
  file_too_large = models.BooleanField(default=False)

  def save(self, *args, **kwargs):
    if self.text:
      try:
        filename = kwargs.pop('filename')
      except:
        filename = Patch.objects.filter(Q(content=self) | Q(patched_content=self)).all()[0].filename
      formatter = HtmlFormatter(nowrap=True, style='colorful')
      try:
        lexer = get_lexer_for_filename(filename)
      except ClassNotFound:
        lexer = TextLexer()
      self.highlighted_text = highlight(self.text, lexer, formatter)
    super(Content, self).save(*args, **kwargs)

  @property
  def lines(self):
    """The text split into lines, retaining line endings."""
    if not self.text:
      return []
    return self.text.splitlines(True)

  @property
  def highlighted_lines(self):
    """The highlighted text split into lines, retaining line endings."""
    if not self.highlighted_text:
      return []
    return self.highlighted_text.splitlines(True)



class Patch(models.Model):
  """A single patch, i.e. a set of changes to a single file.

  This is a descendant of a PatchSet.
  """

  patchset = models.ForeignKey(PatchSet) # == parent
  filename = models.CharField(max_length=500)
  status = models.CharField(max_length=100, null=True, blank=True) # 'A', 'A  +', 'M', 'D' etc
  text = models.TextField(null=True, blank=True)
  content = models.ForeignKey(Content, null=True, blank=True)
  patched_content = models.ForeignKey(Content, related_name='patch2_set', null=True, blank=True)
  is_binary = models.BooleanField(default=False)
  # Ids of patchsets that have a different version of this file.
  delta = models.ManyToManyField(PatchSet, related_name='deltas')
  delta_calculated = models.BooleanField(default=False)

  _lines = None

  @property
  def lines(self):
    """The patch split into lines, retaining line endings.

    The value is cached.
    """
    if self._lines is not None:
      return self._lines
    if not self.text:
      lines = []
    else:
      lines = self.text.splitlines(True)
    self._lines = lines
    return lines

  _property_changes = None

  @property
  def property_changes(self):
    """The property changes split into lines.

    The value is cached.
    """
    if self._property_changes != None:
      return self._property_changes
    self._property_changes = []
    match = re.search('^Property changes on.*\n'+'_'*67+'$', self.text,
                      re.MULTILINE)
    if match:
      self._property_changes = self.text[match.end():].splitlines()
    return self._property_changes

  _num_added = None

  @property
  def num_added(self):
    """The number of line additions in this patch.

    The value is cached.
    """
    if self._num_added is None:
      self._num_added = self.count_startswith('+') - 1
    return self._num_added

  _num_removed = None

  @property
  def num_removed(self):
    """The number of line removals in this patch.

    The value is cached.
    """
    if self._num_removed is None:
      self._num_removed = self.count_startswith('-') - 1
    return self._num_removed

  _num_chunks = None

  @property
  def num_chunks(self):
    """The number of 'chunks' in this patch.

    A chunk is a block of lines starting with '@@'.

    The value is cached.
    """
    if self._num_chunks is None:
      self._num_chunks = self.count_startswith('@@')
    return self._num_chunks

  _num_comments = None

  @property
  def num_comments(self):
    """The number of non-draft comments for this patch.

    The value is cached.
    """
    if self._num_comments is None:
      self._num_comments = Comment.objects.filter(patch=self,
                                                  draft=False).count()
    return self._num_comments

  _num_drafts = None

  @property
  def num_drafts(self):
    """The number of draft comments on this patch for the current user.

    The value is expensive to compute, so it is cached.
    """
    if self._num_drafts is None:
      account = Account.objects.get(patchset_issue_user=user.id) #TODO(kle): when this is a Foreign key, refactor
      if account is None:
        self._num_drafts = 0
      else:
        query = Comment.objects.filter(patch=self,
                                       draft=True,
                                       author=account.user)
        self._num_drafts = query.count()
    return self._num_drafts

  def count_startswith(self, prefix):
    """Returns the number of lines with the specified prefix."""
    return len([l for l in self.lines if l.startswith(prefix)])

  def get_content(self):
    """Get self.content, or fetch it if necessary.

    This is the content of the file to which this patch is relative.

    Returns:
      a Content instance.

    Raises:
      engine.FetchError: If there was a problem fetching it.
    """
    if self.content.is_bad:
      msg = 'Bad content. Try to upload again.'
      logging.warn('Patch.get_content: %s', msg)
      raise engine.FetchError(msg)
    if self.content.is_uploaded and self.content.text == None:
      msg = 'Upload in progress.'
      logging.warn('Patch.get_content: %s', msg)
      raise engine.FetchError(msg)
    else:
      return self.content

  def get_patched_content(self):
    """Get self.patched_content, computing it if necessary.

    This is the content of the file after applying this patch.

    Returns:
      a Content instance.

    Raises:
      engine.FetchError: If there was a problem fetching the old content.
    """
    if self.patched_content is not None:
      return self.patched_content

    old_lines = self.get_content().text.splitlines(True)
    logging.info('Creating patched_content for %s', self.filename)
    chunks = patching.ParsePatchToChunks(self.lines, self.filename)
    new_lines = []
    for tag, old, new in patching.PatchChunks(old_lines, chunks):
      new_lines.extend(new)
    text = unicode(''.join(new_lines))
    patched_content = Content(text=text)
    patched_content.save(filename=self.filename)
    self.patched_content = patched_content
    self.save()
    return patched_content

  @property
  def no_base_file(self):
    """Returns True iff the base file is not available."""
    return self.content and self.content.file_too_large

Bucket = namedtuple('Bucket', ['text', 'quoted'])

class Comment(models.Model):
  """A Comment for a specific line of a specific file.

  This is a descendant of a Patch.
  """

  patch = models.ForeignKey(Patch)  # == parent
  author = models.ForeignKey(User)
  date = models.DateTimeField(auto_now=True)
  lineno = models.IntegerField()
  text = models.TextField()
  left = models.BooleanField()
  draft = models.BooleanField(default=True)


  def complete(self, patch):
    """Set the shorttext and buckets attributes."""
    # TODO(guido): Turn these into caching proprties instead.

    # The strategy for buckets is that we want groups of lines that
    # start with > to be quoted (and not displayed by
    # default). Whitespace-only lines are not considered either quoted
    # or not quoted. Same goes for lines that go like "On ... user
    # wrote:".
    cur_bucket = []
    quoted = None
    self.buckets = []

    def _Append():
      if cur_bucket:
        self.buckets.append(Bucket(text="\n".join(cur_bucket),
                                   quoted=bool(quoted)))

    lines = self.text.splitlines()
    for line in lines:
      if line.startswith("On ") and line.endswith(":"):
        pass
      elif line.startswith(">"):
        if quoted is False:
          _Append()
          cur_bucket = []
        quoted = True
      elif line.strip():
        if quoted is True:
          _Append()
          cur_bucket = []
        quoted = False
      cur_bucket.append(line)

    _Append()

    self.shorttext = self.text.lstrip()[:50].rstrip()
    # Grab the first 50 chars from the first non-quoted bucket
    for bucket in self.buckets:
      if not bucket.quoted:
        self.shorttext = bucket.text.lstrip()[:50].rstrip()
        break


### Accounts ###


class Account(models.Model):
  """Maps a user or email address to a user-selected nickname, and more.

  Nicknames do not have to be unique.

  The default nickname is generated from the email address by
  stripping the first '@' sign and everything after it.  The email
  should not be empty nor should it start with '@' (AssertionError
  error is raised if either of these happens).

  This also holds a list of ids of starred issues.  The expectation
  that you won't have more than a dozen or so starred issues (a few
  hundred in extreme cases) and the memory used up by a list of
  integers of that size is very modest, so this is an efficient
  solution.  (If someone found a use case for having thousands of
  starred issues we'd have to think of a different approach.)
  """

  user = models.ForeignKey(User)
  email = models.EmailField()
  nickname = models.CharField(max_length=50)
  default_context = models.IntegerField(default=engine.DEFAULT_CONTEXT,
                                        choices=[(x,x) for x in CONTEXT_CHOICES])
  default_column_width = models.IntegerField(default=engine.DEFAULT_COLUMN_WIDTH)
  created = models.DateTimeField(auto_now_add=True)
  modified = models.DateTimeField(auto_now=True)
  stars = models.ManyToManyField(Issue)
  fresh = models.BooleanField()
  uploadpy_hint = models.BooleanField(default=True)
  notify_by_email = models.BooleanField(default=True)
  xsrf_secret = models.TextField(null=True, blank=True)

  @classmethod
  def get_account_for_user(cls, user):
    """Get the Account for a user, creating a default one if needed."""
    if user.is_anonymous():
      return None
    try:
      account = cls.objects.get(email=user.email)
    except cls.DoesNotExist:
      nickname = cls.create_nickname_for_user(user)
      account = cls(user=user, email=user.email, nickname=nickname, fresh=True)
      account.save()
    return account

  @classmethod
  def create_nickname_for_user(cls, user):
    """Returns a unique nickname for a user."""
    name = nickname = user.email.split('@', 1)[0]
    existing_nicks = [account.nickname.lower()
                      for account in cls.objects.filter(nickname__istartswith="%s" % nickname)]
    suffix = 0
    while nickname.lower() in existing_nicks:
      suffix += 1
      nickname = '%s%d' % (name, suffix)
    return nickname

  @classmethod
  def get_nickname_for_user(cls, user):
    """Get the nickname for a user."""
    return cls.get_account_for_user(user).nickname

  @classmethod
  def get_account_for_email(cls, email):
    """Get the Account for an email address, or return None."""
    assert email
    try:
      account = cls.objects.get(email=email) #TODO(kle): refactor when email is removed from accounts
    except cls.DoesNotExist:
      account = None
    return account

  @classmethod
  def get_accounts_for_emails(cls, emails):
    """Get the Accounts for each of a list of email addresses."""
    return cls.objects.filter(email__in=emails)

  @classmethod
  def get_nickname_for_email(cls, email, default=None):
    """Get the nickname for an email address, possibly a default.

    If default is None a generic nickname is computed from the email
    address.

    Args:
      email: email address.
      default: If given and no account is found, returned as the default value.
    Returns:
      Nickname for given email.
    """
    account = cls.get_account_for_email(email)
    if account is not None and account.nickname:
      return account.nickname
    if default is not None:
      return default
    return email.replace('@', '_')

  @classmethod
  def get_account_for_nickname(cls, nickname):
    """Get the list of Accounts that have this nickname."""
    assert nickname
    assert '@' not in nickname
    try:
      account = cls.objects.get(nickname__iexact=nickname)
    except cls.DoesNotExist:
      account = None
    return account

  @classmethod
  def get_email_for_nickname(cls, nickname):
    """Turn a nickname into an email address.

    If the nickname is not unique or does not exist, this returns None.
    """
    account = cls.get_account_for_nickname(nickname)
    if account is None:
      return None
    return account.email

  def user_has_selected_nickname(self):
    """Return True if the user picked the nickname.

    Normally this returns 'not self.fresh', but if that property is
    None, we assume that if the created and modified timestamp are
    within 2 seconds, the account is fresh (i.e. the user hasn't
    selected a nickname yet).  We then also update self.fresh, so it
    is used as a cache and may even be written back if we're lucky.
    """
    if self.fresh is None:
      delta = self.created - self.modified
      # Simulate delta = abs(delta)
      if delta.days < 0:
        delta = -delta
      self.fresh = (delta.days == 0 and delta.seconds < 2)
    return not self.fresh

  _drafts = None

  @property
  def drafts(self):
    """A list of issue ids that have drafts by this user.

    This is cached in memcache.
    """
    if self._drafts is None:
      if self._initialize_drafts():
        self._save_drafts()
    return self._drafts

  def update_drafts(self, issue, have_drafts=None):
    """Update the user's draft status for this issue.

    Args:
      issue: an Issue instance.
      have_drafts: optional bool forcing the draft status.  By default,
          issue.num_drafts is inspected (which may query the datastore).

    The Account is written to the datastore if necessary.
    """
    dirty = False
    if self._drafts is None:
      dirty = self._initialize_drafts()
    if have_drafts is None:
      have_drafts = bool(issue.num_drafts(self.user))  # Beware, this may do a query.
    if have_drafts:
      if issue.id not in self._drafts:
        self._drafts.append(issue.id)
        dirty = True
    else:
      if issue.id in self._drafts:
        self._drafts.remove(issue.id)
        dirty = True
    if dirty:
      self._save_drafts()

  def _initialize_drafts(self):
    """Initialize self._drafts from scratch.

    This mostly exists as a schema conversion utility.

    Returns:
      True if the user should call self._save_drafts(), False if not.
    """
    drafts = cache.get('user_drafts:' + self.email)
    if drafts is not None:
      self._drafts = drafts
      ##logging.info('HIT: %s -> %s', self.email, self._drafts)
      return False
    # We're looking for the Issue key id.  The ancestry of comments goes:
    # Issue -> PatchSet -> Patch -> Comment.
    issue_ids = set(comment.patch.patchset.issue.id
                    for comment in Comment.objects.filter(author=self.user,
                                                          draft=True))
    self._drafts = list(issue_ids)
    ##logging.info('INITIALIZED: %s -> %s', self.email, self._drafts)
    return True

  def _save_drafts(self):
    """Save self._drafts to memcache."""
    ##logging.info('SAVING: %s -> %s', self.email, self._drafts)
    cache.set('user_drafts:' + self.email, self._drafts, 3600)

  def get_xsrf_token(self, offset=0):
    """Return an XSRF token for the current user."""
    if not self.xsrf_secret:
      self.xsrf_secret = base64.b64encode(os.urandom(8))
      self.save()
    m = md5(self.xsrf_secret)
    email_str = self.email.lower()
    if isinstance(email_str, unicode):
      email_str = email_str.encode('utf-8')
    m.update(email_str)
    when = int(time.time()) // 3600 + offset
    m.update(str(when))
    return m.hexdigest()
