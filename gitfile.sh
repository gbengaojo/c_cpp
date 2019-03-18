# note that origin/master refers to the remote repository

# fetch the changes from the remote
git fetch origin

# show commit logs of changes (what's over there that's not over here?)
# invert arguments to know "what's here that's not there"
git log master..origin/master

# show diffs of changes (inverting arguments just provides a reversed perspective)
git diff master..origin/master

# apply the changes by merge
git merge origin/master

# .. or just pull the changes
git pull
