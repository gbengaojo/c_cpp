# fetch the changes from the remote
git fetch origin

# show commit logs of changes
git log master..origin/master

# show diffs of changes
git diff master..origin/master

# apply the changes by merge
git merge origin/master

# .. or just pull the changes
git pull
