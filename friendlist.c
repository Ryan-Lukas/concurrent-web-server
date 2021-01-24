/*
 * friendlist.c - [Starting code for] a web-based friend-graph manager.
 *
 * Based on:
 *  tiny.c - A simple, iterative HTTP/1.0 Web server that uses the 
 *      GET method to serve static and dynamic content.
 *   Tiny Web server
 *   Dave O'Hallaron
 *   Carnegie Mellon University


 Student: Ryan Lukas
 Date: 4/27/20
 Assignment: cs4400 hw6
 */
#include "csapp.h"
#include "dictionary.h"
#include "more_string.h"

static void doit(int fd);
static dictionary_t *read_requesthdrs(rio_t *rp);
static void read_postquery(rio_t *rp, dictionary_t *headers, dictionary_t *d);
static void clienterror(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg);
static void print_stringdictionary(dictionary_t *d);
//static void serve_request(int fd, dictionary_t *query);
static void serve_friends(int fd, dictionary_t *query);
static void serve_befriend(int fd, dictionary_t *query);
static void serve_unfriend(int fd, dictionary_t *query);
static void serve_introduce(int fd, dictionary_t *query);

static void *doitfunc(void *connfdp);
dictionary_t *friends;
pthread_mutex_t lock;

int main(int argc, char **argv) {
  int listenfd, connfd;
  char hostname[MAXLINE], port[MAXLINE];
  socklen_t clientlen;
  struct sockaddr_storage clientaddr;

  /* Check command line args */
  if (argc != 2) {
    fprintf(stderr, "usage: %s <port>\n", argv[0]);
    exit(1);
  }
  pthread_mutex_init(&lock, NULL);
  listenfd = Open_listenfd(argv[1]);
  
  //must create dictionary for each users friends exactly like query
  friends = (dictionary_t*)make_dictionary(COMPARE_CASE_SENS,free);
  /* Don't kill the server if there's an error, because
     we want to survive errors due to a client. But we
     do want to report errors. */
  exit_on_error(0);

  /* Also, don't stop on broken connections: */
  Signal(SIGPIPE, SIG_IGN);

  while (1) {
    clientlen = sizeof(clientaddr);
    connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);
    if (connfd >= 0) {
      Getnameinfo((SA *) &clientaddr, clientlen, hostname, MAXLINE, 
                  port, MAXLINE, 0);
      printf("Accepted connection from (%s, %s)\n", hostname, port);
      
      int *connfd2;
      pthread_t thread;
      connfd2 = malloc(sizeof(int));
      *connfd2 = connfd;
      Pthread_create(&thread, NULL, doitfunc, connfd2); // must bring to other function
      Pthread_detach(thread);

      
      //doit(connfd);
      //Close(connfd);
    }
  }
}

void *doitfunc(void *connfd2){
  int connfd = *(int*)connfd2;
  free(connfd2);
  doit(connfd);
  Close(connfd);
  return NULL;

}

/*
 * doit - handle one HTTP request/response transaction
 */
void doit(int fd) {
  char buf[MAXLINE], *method, *uri, *version;
  rio_t rio;
  dictionary_t *headers, *query;

  /* Read request line and headers */
  Rio_readinitb(&rio, fd);
  if (Rio_readlineb(&rio, buf, MAXLINE) <= 0)
    return;
  printf("%s", buf);
 
 
  if (!parse_request_line(buf, &method, &uri, &version)) {
    clienterror(fd, method, "400", "Bad Request",
                "Friendlist did not recognize the request");
  } else {
    if (strcasecmp(version, "HTTP/1.0")
        && strcasecmp(version, "HTTP/1.1")) {
      clienterror(fd, version, "501", "Not Implemented",
                  "Friendlist does not implement that version");
    } else if (strcasecmp(method, "GET")
               && strcasecmp(method, "POST")) {
      clienterror(fd, method, "501", "Not Implemented",
                  "Friendlist does not implement that method");
    } else {
      headers = read_requesthdrs(&rio);

      /* Parse all query arguments into a dictionary */
      query = make_dictionary(COMPARE_CASE_SENS, free);
      parse_uriquery(uri, query);
      if (!strcasecmp(method, "POST"))
        read_postquery(&rio, headers, query);

      /* For debugging, print the dictionary */
      print_stringdictionary(query);

      /* You'll want to handle different queries here,
         but the intial implementation always returns
         nothing: */

      if(starts_with("/friends",uri)){
	pthread_mutex_lock(&lock);
	serve_friends(fd, query);
	pthread_mutex_unlock(&lock);
      }else if(starts_with("/befriend",uri)){
	pthread_mutex_lock(&lock);
	serve_befriend(fd, query);
	pthread_mutex_unlock(&lock);
      }else if(starts_with("/unfriend",uri)){
	pthread_mutex_lock(&lock);
	serve_unfriend(fd, query);
	pthread_mutex_unlock(&lock);
      }else if(starts_with("/introduce",uri)){
	serve_introduce(fd, query);
	//locks inside method
      }
      
      /* Clean up */
      free_dictionary(query);
      free_dictionary(headers);
      }

    /* Clean up status line */
    free(method);
    free(uri);
    free(version);
  }
}

/*
 * read_requesthdrs - read HTTP request headers
 */
dictionary_t *read_requesthdrs(rio_t *rp) {
  char buf[MAXLINE];
  dictionary_t *d = make_dictionary(COMPARE_CASE_INSENS, free);

  Rio_readlineb(rp, buf, MAXLINE);
  printf("%s", buf);
  while(strcmp(buf, "\r\n")) {
    Rio_readlineb(rp, buf, MAXLINE);
    printf("%s", buf);
    parse_header_line(buf, d);
  }
  
  return d;
}

void read_postquery(rio_t *rp, dictionary_t *headers, dictionary_t *dest) {
  char *len_str, *type, *buffer;
  int len;
  
  len_str = dictionary_get(headers, "Content-Length");
  len = (len_str ? atoi(len_str) : 0);

  type = dictionary_get(headers, "Content-Type");
  
  buffer = malloc(len+1);
  Rio_readnb(rp, buffer, len);
  buffer[len] = 0;

  if (!strcasecmp(type, "application/x-www-form-urlencoded")) {
    parse_query(buffer, dest);
  }

  free(buffer);
}

static char *ok_header(size_t len, const char *content_type) {
  char *len_str, *header;
  
  header = append_strings("HTTP/1.0 200 OK\r\n",
                          "Server: Friendlist Web Server\r\n",
                          "Connection: close\r\n",
                          "Content-length: ", len_str = to_string(len), "\r\n",
                          "Content-type: ", content_type, "\r\n\r\n",
                          NULL);
  free(len_str);

  return header;
}

static void serve_introduce(int fd, dictionary_t *query){
  char *body, *header;
  size_t bodylen;
  
  if(dictionary_count(query) != 4){
    clienterror(fd, "POST", "400", "Bad Request", "Not enough arguements.");
    return;
  }

  const char* myUser = dictionary_get(query, "user");
  const char* friend = dictionary_get(query, "friend");

  char* host = (char*)dictionary_get(query,"host");
  char* port = (char*)dictionary_get(query,"port");

  body ="";

  char buffer[MAXBUF];
  
  int connfd = Open_clientfd(host, port);
  sprintf(buffer, "GET /friends?user=%s HTTP/1.1\r\n\r\n", query_encode(friend));

  Rio_writen(connfd, buffer, strlen(buffer));
  Shutdown(connfd,SHUT_WR);

  char newbuf[MAXLINE]; 
  rio_t rio;
  Rio_readinitb(&rio, connfd);
  
  if(Rio_readlineb(&rio, newbuf, MAXLINE) <= 0)
    clienterror(fd, "POST", "400", "Bad Request", "Can't read from requested server.");

  char *status, *version, *desc;
  if(!parse_request_line(newbuf, &version, &status, &desc))
    clienterror(fd, "GET", "400", "Bad Request", "Didn't recognize the request");
  else{
    if(strcasecmp(version, "HTTP/1.0") && strcasecmp(version, "HTTP/1.1"))
      clienterror(fd, version, "501", "Not Implemented", "Doesn't support that version");
    else if (strcasecmp(status, "200") && strcasecmp(desc, "OK"))
      clienterror(fd, status, "501", "Not Implemented", "Recieved isn't correct");
    else{
      dictionary_t *headers = read_requesthdrs(&rio);
      char *strlength = dictionary_get(headers, "Content-length");
      
      int length = (strlength ? atoi(strlength) :0 ); 
      char rbuf[length];
      
      printf("len = %d\n", length);
      if(length <= 0)
	clienterror(fd, "GET", "400", "Bad Request", "No friends recieved");
      else{
	print_stringdictionary(headers);

	Rio_readnb(&rio, rbuf, length);
	rbuf[length] = 0;
	
	pthread_mutex_lock(&lock);

	dictionary_t *myDic = dictionary_get(friends, myUser); 
	if(myDic == NULL){
	  myDic = make_dictionary(0, NULL);
	  dictionary_set(friends, myUser, myDic);
	}

	char** newFriends = split_string(rbuf, '\n');

	int x;
	for(x = 0; newFriends[x] != NULL; x++){
	  if(strcmp(newFriends[x],myUser) == 0)
	    continue;

	  dictionary_t* newfriend = (dictionary_t*)dictionary_get(friends, myUser);
	  if(newfriend == NULL){
	    newfriend = (dictionary_t*)make_dictionary(0,free);
	    dictionary_set(friends, myUser, newfriend);
	  }
	  if(dictionary_get(newfriend, newFriends[x]) == NULL){
	    dictionary_set(newfriend, newFriends[x], NULL);
	  }

	  dictionary_t* newfriendrequest = (dictionary_t*)dictionary_get(friends, newFriends[x]);
	  if(newfriendrequest == NULL){
	    newfriendrequest = (dictionary_t*)make_dictionary(COMPARE_CASE_SENS,free);
	    dictionary_set(friends, newFriends[x], newfriendrequest);
	  }
	  if(dictionary_get(newfriendrequest, myUser) == NULL)
	    dictionary_set(newfriendrequest, myUser, NULL);
	  
	  free(newFriends[x]);
	}
	free(newFriends);

	const char** list = dictionary_keys(myDic);

	body = join_strings(list,'\n');

	pthread_mutex_unlock(&lock);
	
	bodylen = strlen(body);
	
	header = ok_header(bodylen, "text/html; charset=utf-8");
	Rio_writen(fd, header, strlen(header));
	printf("Response headers:\n");
	printf("%s", header);

	free(header);

	Rio_writen(fd, body, bodylen);
	
	free(body);
      }
    }
    free(version);
    free(status);
    free(desc);
  }
  Close(connfd);
    
}

static void serve_unfriend(int fd, dictionary_t *query){
  size_t len;
  char *body, *header;

  if(dictionary_count(query) != 2){
    clienterror(fd, "POST", "400", "Bad Request", "Not enough individuals");
  }
  
  const char* myUser = (char*)dictionary_get(query, "user");
  dictionary_t* checkUser = (dictionary_t*)dictionary_get(friends, myUser);

  if(myUser == NULL){
    clienterror(fd, "POST", "400", "Bad Request", "Not a valid user");
  }
  if(checkUser == NULL){
    clienterror(fd, "POST", "400", "Bad Request", "User isn't inside dictionary");
  }

  char** unfriendpointer = split_string((char*)dictionary_get(query, "friends"),'\n');

  int x;
  for(x = 0; unfriendpointer[x] != NULL; x++){
    dictionary_remove(checkUser, unfriendpointer[x]);
    
    //remove from friends list
    dictionary_t* rmfriend = (dictionary_t*)dictionary_get(friends, unfriendpointer[x]);
    
    if(rmfriend != NULL)
      dictionary_remove(rmfriend, myUser);

  }

  dictionary_t* check = (dictionary_t*)dictionary_get(friends, myUser);
  const char** allfriends = dictionary_keys(check);

  body = join_strings(allfriends, '\n');
  
  len = strlen(body);

  header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response header:\n");
  printf("%s",header);
  
  free(header);

  Rio_writen(fd, body, len);

}
 
static void serve_befriend(int fd, dictionary_t *query){
  size_t len;
  char *body, *header;
  
  if(query == NULL){
    clienterror(fd,"POST", "400", "Bad Request", "No query");
  }
  if(dictionary_count(query) != 2){ //must have more than 2 individuals for befriend
    clienterror(fd, "POST", "400", "Bad Request", "Not enough individuals");
  }

  
  const char* myUser = (char*)dictionary_get(query, "user");
  dictionary_t* checkUser = (dictionary_t*)dictionary_get(friends, myUser);
  if(checkUser == NULL){ //checks to see if there is a friend list with user
    dictionary_t* newfriendslist = (dictionary_t*)make_dictionary(0,free);
    dictionary_set(friends, myUser, newfriendslist);
  }

  char** newFriendpointer = split_string((char*)dictionary_get(query, "friends"),'\n');

  if(newFriendpointer == NULL){
    clienterror(fd, "POST", "400", "Bad Request", "Not a valid friend");
  }

  int x;
  for(x = 0; newFriendpointer[x] != NULL; x++){
    
     //if it's the same person, continue, don't re-add
    if(strcmp(newFriendpointer[x],myUser)==0)
       continue;

    dictionary_t* temp = (dictionary_t*)dictionary_get(friends, myUser);

    if(dictionary_get(temp, newFriendpointer[x]) == NULL){
	   dictionary_set(temp, newFriendpointer[x],NULL); //adds new friend to user
    }
      
    dictionary_t* tempnew = (dictionary_t*)dictionary_get(friends, newFriendpointer[x]);
      //if the new friend doesn't exist, create new dictionary and add to friends list
    if(tempnew == NULL){
        tempnew = (dictionary_t*)make_dictionary(COMPARE_CASE_SENS,free);
	dictionary_set(friends, newFriendpointer[x], tempnew);
    }
    if(dictionary_get(tempnew,myUser) == NULL){
	dictionary_set(tempnew,myUser,NULL); // add myUser to new friends list
    }
   
  }
 
 
  dictionary_t* check = (dictionary_t*)dictionary_get(friends,myUser);
  const char** allfriends = dictionary_keys(check);
  
  body = join_strings(allfriends, '\n');
  
  len = strlen(body);

  /*Send response headers to client */
  
  header = ok_header(len, "text/http; charset=uty-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s",header);

  free(header);

  Rio_writen(fd,body,len);
  
 
}


/*returns the friends of the user, with each on a separate newline-terminated line as plain text. 
  The result is empty if no friends have been registered for the user.
  The result can report the friends of the user in any order

 */
static void serve_friends(int fd, dictionary_t *query){
  size_t len;
  char *body, *header;
 
  //checking to see if a valid user
  if(dictionary_count(query) !=1){
    clienterror(fd, "GET", "400", "Bad Request", "Must need a user.");
  }
  
  const char* user = dictionary_get(query, "user");
  body = "";
  
  if(user == NULL){
    clienterror(fd, "GET", "400", "Bad Request", "Invalid User.");
  }

  //pull friends from friends dictionary
  dictionary_t *addtolist = dictionary_get(friends, user);
  
  if(addtolist != NULL){
    const char **list = dictionary_keys(addtolist);
    body = join_strings(list,'\n');
  }
  
  len = strlen(body);

  /* Send response headers to client */
  header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);


  free(header);
 
  Rio_writen(fd, body, len);
  
  //free(body);
}

 
/*
 * serve_request - example request handler
 */

/*
static void serve_request(int fd, dictionary_t *query) {
  size_t len;
  char *body, *header;

  body = strdup("alice\nbob");

  len = strlen(body);

  
  header = ok_header(len, "text/html; charset=utf-8");
  Rio_writen(fd, header, strlen(header));
  printf("Response headers:\n");
  printf("%s", header);

  free(header);

  
  Rio_writen(fd, body, len);

  free(body);
}
*/
/*
 * clienterror - returns an error message to the client
 */
void clienterror(int fd, char *cause, char *errnum, 
		 char *shortmsg, char *longmsg) {
  size_t len;
  char *header, *body, *len_str;

  body = append_strings("<html><title>Friendlist Error</title>",
                        "<body bgcolor=""ffffff"">\r\n",
                        errnum, " ", shortmsg,
                        "<p>", longmsg, ": ", cause,
                        "<hr><em>Friendlist Server</em>\r\n",
                        NULL);
  len = strlen(body);

  /* Print the HTTP response */
  header = append_strings("HTTP/1.0 ", errnum, " ", shortmsg, "\r\n",
                          "Content-type: text/html; charset=utf-8\r\n",
                          "Content-length: ", len_str = to_string(len), "\r\n\r\n",
                          NULL);
  free(len_str);
  
  Rio_writen(fd, header, strlen(header));
  Rio_writen(fd, body, len);

  free(header);
  free(body);
}

static void print_stringdictionary(dictionary_t *d) {
  int i, count;

  count = dictionary_count(d);
  for (i = 0; i < count; i++) {
    printf("%s=%s\n",
           dictionary_key(d, i),
           (const char *)dictionary_value(d, i));
  }
  printf("\n");
}
