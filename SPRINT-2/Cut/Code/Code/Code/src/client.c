#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"

#define PORT 4444
#define SEND_BUFFER_SIZE 512
#define RECV_BUFFER_SIZE 512

#define MSG_SUCCESS  1
#define MSG_FAIL     2
#define MSG_INVALID  3
#define MAX_INPUT_LEN   32
#define ENCRYPT      4
#define DECRYPT      5

int cl_sock_fd;

char send_buffer[SEND_BUFFER_SIZE];
char recv_buffer[RECV_BUFFER_SIZE];


int validate_file_name_and_option (char *filename, int option)
{
  // validate the file is present or not 
  // validate the enc option 1 & 2
  if ((option < 1) || (option > 2))
  {
    printf("Invalid encrypt/decrypt option \n");
    return -1;
  }
  
  return 0;
}

void handle_server_close (int sockfd)
{

  close(sockfd);

}

int process_enc_dec_msg(char *fname, int option, int type)
{
  int ret; 
  msg_t msg, *rx_msg;

  memset(msg.msg_data, '\0', sizeof(msg.msg_data));
  memset(msg.msg_add_data, '\0', sizeof(msg.msg_add_data));

  if (type == ENCRYPT)
  {
    if (option == 1)
      msg.msg_type = MSG_BASIC_ENCRYPT;
    else if (enc_option == 2)
      msg.msg_type = MSG_ADVANCED_ENCRYPT;
  }
  else if (type == DECRYPT)
  {
    if (option == 1)
      msg.msg_type = MSG_BASIC_DECRYPT;
    else if (enc_option == 2)
      msg.msg_type = MSG_ADVANCED_DECRYPT;
  }

  strncpy(msg.msg_data, fname, strlen(fname));

  printf("Messaage Created \n");
  printf("  Type: %d \n", msg.msg_type);
  printf("  Data: %s len = %ld \n", msg.msg_data, strlen(uname));
  printf("  Additional Data: %s len = %ld\n", msg.msg_add_data,strlen(pwd));

  ret = send(cl_sock_fd, (char *) &msg, sizeof(msg), 0);

  printf("Sent bytes = %d \n", ret);

  ret = recv(cl_sock_fd, (char *) recv_buffer, sizeof(recv_buffer), 0);

  printf("Received %d bytes from Server \n", ret);

  if (ret == 0)
  {
    printf("%s():%d Server has closed on socket fd = %d \n",
        __FUNCTION__, __LINE__, cl_sock_fd);

    handle_server_close(cl_sock_fd);

    return -2;
  }

  rx_msg = (msg_t *) recv_buffer;

  return rx_msg->msg_type;
}

void handle_client_close(int sock_fd)
{

  /* TODO */
  close(sock_fd);

}

int main()
{
  int ret;
  int i, option;

  struct sockaddr_in server_addr;

  int  enc_option;
  int  dec_option;
  char filename[MAX_INPUT_LEN];

  cl_sock_fd = socket(AF_INET,SOCK_STREAM, 0);

  if (cl_sock_fd < 0) 
  {
    printf("Error in connection.\n");
    exit(1);
  }

  printf("Client Socket is created.\n");

  memset(send_buffer, '\0', sizeof(send_buffer));
  memset(recv_buffer, '\0', sizeof(recv_buffer));

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(PORT);

  server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  ret = connect(cl_sock_fd, (struct sockaddr*)&server_addr,
      sizeof(server_addr));

  if (ret < 0) 
  {
    printf("Error in connection.\n");
    exit(1);
  }

  printf("Connected to Server.\n");

  while(1)
  {
    printf(" Welcome to Encryption and decryption of file \n");
    printf("===================================\n");

    printf("1. Encrpt the given file \n");
    printf("2. Decrypt the given file\n");
    printf("3. Display the details of file \n");
    printf("4. Exit\n");

    printf("Enter option: ");
    scanf("%d", &option);

    switch(option)
    {
      case 1:
        {
          printf("Choose the file to be encrypted");
          gets(fname);
          printf("Choose the algorithm to perform encryption");
          printf("1. Basic Encryption \n");
          printf("2. Advanced Encryption \n");
          scanf("%d", &enc_option);
          ret = validate_file_name_and_option (fname, enc_option);

          if (ret < 0)
          {
             printf("invalid file name or encryption \n");
             continue;
          }

          ret = process_enc_dec_msg(fname, enc_option, ENCRYPT);

          if (ret == MSG_ENC_SUCCESS)
          {
             printf("Encryption successful \n");
          }
          else if (ret == MSG_ENC_FAIL)
          {
             printf("Encryption failed \n");
          }
          else
          {
             printf("Invalid response from server \n");
          }
          break;
        }


      case 2:
        {
          printf("Choose the file to be decrypted");
          gets(fname);
          printf("Choose the algorithm to perform decryption");
          printf("1. Basic Decryption \n");
          printf("2. Advanced Decryption \n");
          scanf("%d", &dec_option);
          ret = validate_file_name_and_option (fname, option);

          if (ret < 0)
          {
             printf("invalid file name or encryption \n");
             continue;
          }

          ret = process_enc_dec_msg(fname, dec_option, DECRYPT);

          if (ret == MSG_DEC_SUCCESS)
          {
             printf("Decryption successful \n");
          }
          else if (ret == MSG_DEC_FAIL)
          {
             printf("Decryption failed \n");
          }
          else
          {
             printf("Invalid response from server \n");
          }
          break;
        }

          break;
        }

      case 3:
        {
          printf("The statistics of file");

          stat(fname);

          encrypt(fname,algname);

          break;
        }

      case 4: exit();
              return;
      default:
              printf("Invalid option .. enter between 1 to 4 \n");
              continue;
    }
  }

  memset(menu_data_string1, '\0', sizeof(menu_data_string1));
  memset(menu_data_string2, '\0', sizeof(menu_data_string2));

  printf("S1: %s \n", menu_data_string1);
  printf("S2: %s \n", menu_data_string2);
  switch(option)
  {
    case 1:

      ret = get_and_validate_input(menu_data_string1, menu_data_string2);

      if (ret == -1)
      {
        printf("Invalid input format \n");
        break;
      }

      ret = proces_uname_pwd_msg(menu_data_string1, menu_data_string2);

      if (ret == MSG_FAIL)
      {
        printf("User Authentication Failed \n");
        break;
      }
      else if (ret == MSG_INVALID)
      {
        printf("User Authentication Failed \n");
        break;

      }
      else if (ret == MSG_SUCCESS)
      {
        printf("User Authentication Success \n");

        display_hotel_menu();
      }

      break;

    case 2:

      ret = get_and_validate_input(menu_data_string1, menu_data_string2);

      if (ret == -1)
      {
        printf("Invalid input format \n");
        break;
      }

      ret = proces_login_msg(menu_data_string1, menu_data_string2);

      if (ret == MSG_FAIL)
      {
        printf("User Authentication Failed \n");
        break;
      }
      else if (ret == MSG_INVALID)
      {
        printf("User Authentication Failed \n");
        break;

      }
      else if (ret == MSG_SUCCESS)
      {
        printf("User Authentication Success \n");

        display_hotel_menu();
      }

      break;

    case 3:
      exit(0);

    default:
      printf("Invalid Option .. \n");
      break;
  }

}

return 0;
}

