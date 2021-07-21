## Bouncy castle dependency update procedure

### Update our private mirror

We need to manually update our fork with the latest upstream. We need to do the following steps:

Clone the private bouncy castle repository in our machine:

```bash
git clone git@github.com:form3tech/fork-bc-java.git
```

Add the upstream remote:

```bash
git remote add upstream git@github.com:bcgit/bc-java.git
```

Fetch the changes from the upstream project:

```
git fetch upstream
git fetch upstream --tags
```

Sync our master branch

```bash
git checkout master
git merge upstream/master
git push && git push --tags
```

We are back porting the changes to a branch called `form3-patch` , so now we need to merge the new version changes. This can be achieved with the following commands:

```
## Create a new branch from the patched one.
git checkout form3-patch
git checkout -b form3-patch-update-to-version-<version>

## Update your local working branch with the changes of master
git merge <target-version-tag-from-master>
git push 
```

Once the push is done, you can create a PR from your working branch to the the patched one. In that moment tests will run. Once approved and merged, the CI will publish the dependency and you can import it in your projects:

```bash
"org.bouncycastle:form3-bc-pkix:${bouncycastleVersion}"
```

## Some notes around the patch implementation

We aimed to do as little changes as possible on this codebase in order to prevent future conflicts. Also, at the time of this write, we are not getting feedback in the [upstream issue](https://github.com/bcgit/bc-java/issues/986) we opened. That is the reason because you will no see an elegant solution in code. Just the minor change that will made our services work.

As a security measure, we implemented a signature test that will run in the CI before merging. This will ensure the expected output.

We needed to add some gradle plugins in order to publish to the Form3 AWS S3 releases bucket. This project has 2 ways of compiling the needed JAR:

* Via apache ant (through gradle integration) using the native build script. (TODO. Link to the branch here)
* By using the gradle publication. In this one, we had to ensure that transitive dependencies points to the gradle.

The solution described above is implemented in code on this diff (TODO link to the diff among `form3-patch` and master)