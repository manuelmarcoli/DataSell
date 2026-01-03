const { execSync } = require('child_process');
const path = require('path');

const repoPath = 'c:\\Users\\HEDGEHOG\\Downloads\\DataSell-main';
process.chdir(repoPath);

try {
  console.log('Fetching latest from remote...');
  execSync('git fetch origin main 2>&1', { stdio: 'inherit' });
  
  console.log('\nChecking current branch...');
  const currentBranch = execSync('git rev-parse --abbrev-ref HEAD', { encoding: 'utf-8' }).trim();
  console.log('Current branch:', currentBranch);
  
  console.log('\nChecking for unpushed commits...');
  execSync('git log origin/main..HEAD --oneline 2>&1 || echo "May have commits to push"', { stdio: 'inherit' });
  
  console.log('\nPushing master branch to origin main...');
  execSync('git push origin master:main 2>&1', { stdio: 'inherit' });
  
  console.log('\nVerifying push...');
  execSync('git log origin/main --oneline -n 5 2>&1', { stdio: 'inherit' });
  
  console.log('\n✅ Push completed successfully!');
} catch (error) {
  console.error('❌ Error during push:', error.message);
  process.exit(1);
}
