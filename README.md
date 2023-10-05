# Git & GitHub

## Tutorial on using Git and GitHub

**YouTube Video:** \[link]\([(375) Complete Git and GitHub Tutorial for Beginners - YouTube](https://www.youtube.com/watch?v=Ez8F0nW6S-w\&ab\_channel=ApnaCollege))

***

### Cheatsheet

Commands: \[Link]\([git-cheat-sheet-education (mycourse.app)](https://lwfiles.mycourse.app/62a6cd5e1e9e2fbf212d608d-public/publicFiles/git-cheat-sheet-education.pdf))

***

## Git

\-> is a version control system. It is popular, free, & open source.

**Uses:**

1. Tracking History
2. To collaborate

***

## GitHub

\-> Website that allows developers to store and manage their code using Git.

**Terminologies:**

1. **repository**: Folders created in GitHub.
2. **commit**: to final changes.
3. **add**: changes that have been made (add --> commit)

***

## Setting up Git

\-> Install Windows (git bash)

**Configuring Git:**

```bash
git config --global user.name "My Name"
git config --global user.email "someone@email.com"
git config--list
```

**There are two type of changes:**

1. **Global**: configuring for every repo.
2. **Local**: configuring for specific accounts with specific accounts.

**Clone & Status:**

4. **clone**: cloning a repo in our local machine `git clone <link of repo>`
5. **status**: display the status of the code `git status`

**Git Status:**

1. **untracked:** new files that git has not tracked yet.
2. **modified:** files that have been changed
3. **staged:** The file is ready to be committed
4. **unmodified:** unchanged

**Add & Commit:**

1. **add:** adds new or changed files in your working directory to the Git staging area. `git add <file name>`
2. **commit:** it is the record of change `git commit -m <some message>`

**Push:**

* **push:** upload local (machine) repo content to remote (GitHub) repo. `git push origin main`

**Init:**

\-> used to create a new git repo

```bash
git init
git remote add origin <link>
git remote -v    #to verify remote
git branch    #to check the branch
git branch -M main    #to rename branch
git push -u origin main    # -u flag to set upstream, you want to use origin main in future also
```

***

## Workflow

GitHub Repo -> clone -> changes -> add -> commit -> push

***

## Git Branches

\-> If there are a number of groups working on a project, you may need different branches to commit changes to the project for different groups.

**Branch Commands**

```bash
git branch    # to check the branch
git branch -M main    # to rename branch
git checkout <branch-name>    # to navigate
git checkout -b <new-branch-name>    # to create new branch
git branch -d <branch-name>    # to delete a branch
```

***

## Merging Code

1. Way 1

```bash
git diff <branch-name>    # to compare commits, branches, files, and more
git merge <branch-name>    # to merge two branches
```

2. Way 2 -> Create PR (pull request)

* **PR (pull request):** It lets you tell others about changes you've pushed to a branch in a repo on GitHub.

**Pull Command:**

\-> used to fetch and download content from the remote repo and immediately update the local repo to match that content.

```bash
git pull origin main
```

***

## Resolving Merge Conflicts

\-> An event that takes place when Git is unable to automatically resolve differences in code between two commits of two different branches.

```bash
git merge main    # to merge codes of two branches
```

Now, VS Code will show an error (CONFLICT) that, it is unable to decide whose branch's code to keep. It will give you an option on which branch's code to keep. You can also make the changes manually by deleting snippets of code.

After resolving the merge conflict, you'll have to `add` and `commit` that code again.

***

## Undoing Changes

* **Case 1:** staged changes (things have been added but not commit)

```bash
git reset <file-name>
git reset
```

* **Case 2:** commit changes (for one commit)

```bash
git reset HEAD~1
```

!\[\[Pasted image 20231005205857.png]]

* **Case 3:** commit changes (for many commits)

```bash
git reset <commit-hash>    
git reset --hard <commit-hash>    # using hard will change code in VS Code also
```

A hash of a commit can be obtained by using the following command:

```bash
git log
```

***

## Fork

\-> A fork is a new repo that shares code and visibility settings with the original "upstream" repo. Fork is a rough copy.

You can fork other users' repos in your account, make changes (adding features, fixing bugs, etc.), and then request to merge it to their original repo. This is how you can work on other projects.
