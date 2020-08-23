#!/bin/bash

# get current version----------
version=`cat package.json | grep -e '"version":'`
while IFS='"' read -ra ADDR; do
    counter=0
    for i in "${ADDR[@]}"; do
        if [ $counter == 3 ]
        then
            version=$i
        fi
        counter=$(($counter+1))
    done
done <<< "$version"

# get git branch name-----------
branch_name="$(git symbolic-ref HEAD 2>/dev/null)" ||
branch_name="(unnamed branch)"     # detached HEAD

branch_name=${branch_name##refs/heads/}

# check if branch is correct based on the version-----------
if [ $branch_name == "master" ]
then
    YELLOW='\033[1;33m'
    NC='\033[0m' # No Color
    printf "${YELLOW}committing to MASTER${NC}\n"
elif [[ $version == $branch_name* ]]
then
    continue=1
elif ! [[ $branch_name =~ ^[0-9].[0-9]$ ]]
then
    YELLOW='\033[1;33m'
    NC='\033[0m' # No Color
    printf "${YELLOW}Not committing to master or version branches${NC}\n"
else
    RED='\033[0;31m'
    NC='\033[0m' # No Color
    printf "${RED}Pushing to wrong branch. Stopping commit${NC}\n"
    exit 1
fi

echo "BRANCH OK"