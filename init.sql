CREATE TABLE accounts (
    account_id SERIAL PRIMARY KEY,
    oauth_provider VARCHAR(30) NOT NULL, -- For now, it's only google.
    email VARCHAR(40) NOT NULL UNIQUE,
    username VARCHAR(40) NOT NULL,
    -- Created urls can be found on accounts_file table
    created TIMESTAMP NOT NULL DEFAULT NOW()
);
CREATE INDEX account_email ON accounts(email);

CREATE TABLE files (
    commit_id CHAR(64) PRIMARY KEY,
    txt TEXT NOT NULL
);

CREATE TABLE file_data (
  url_code CHAR(7) NOT NULL, -- Duplicates can exist due to versions
  commit_id CHAR(64) PRIMARY KEY, 
  prev_commit CHAR(64) REFERENCES file_data(commit_id), -- SELF Reference in case of null
  next_commit CHAR(64) REFERENCES file_data(commit_id) , -- SELF Reference in case of null
  created TIMESTAMP  NOT NULL DEFAULT NOW(), -- Version timestamp 
  expire TIMESTAMP  NOT NULL, -- Expire deadline
  burn BOOLEAN DEFAULT FALSE, -- If true, file will be deleted after read once
  type VARCHAR(30) NOT NULL, -- File type such as js, py, plain, etc
  category VARCHAR(30), -- Such as code, csv, etc 
  linked_account_id INTEGER REFERENCES accounts(account_id), -- Meant for registered accounts, otherwise its null

  FOREIGN KEY (commit_id) REFERENCES files(commit_id) ON DELETE CASCADE -- Linked with files table
);


CREATE TABLE url_lookup (
    url_code CHAR(7)  PRIMARY KEY, 
    head CHAR(64) REFERENCES file_data(commit_id)  ON DELETE CASCADE, -- Latest file data
    expire TIMESTAMP  NOT NULL,  -- Updates according with latest file data
    pass VARCHAR(30), -- Can be null, if not password protected
    changes_counts INTEGER DEFAULT 1 -- Total version changes
);

CREATE INDEX url_expire ON url_lookup(expire);

-- For checking account files 
CREATE TABLE account_files ( 
    account_id INTEGER REFERENCES accounts(account_id) ON DELETE CASCADE PRIMARY KEY,
    url_code VARCHAR(7) REFERENCES url_lookup(url_code) ON DELETE CASCADE 
);

