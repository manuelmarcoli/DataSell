@echo off
cd /d "c:\Users\HEDGEHOG\Downloads\DataSell-main"
REM Check current status
git status > git_status.txt 2>&1
REM List branches
git branch -a > git_branches.txt 2>&1
REM Try to push master to origin
git push origin master > git_push_master.txt 2>&1
REM Also try to push main
git push origin main >> git_push_master.txt 2>&1
echo Done! Check git_push_master.txt for results
