/*
 * Copyright 2015, Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <scsi/scsi.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <rbd/librbd.h>
#include <rados/librados.h>

#include "tcmu-runner.h"

struct rbd_state{
  char *pool;
  char *name;
  char *snap;
  rados_t cluster;
  rados_ioctx_t ioctx;
  rbd_image_t rbd_image;
  
  unsigned int block_size;
};


/*
 * parse rbd image name 
 */
static int parse_imagepath(char *cfgstring, char **pool, char **name, char **snap)
{
  char *p, *sep;
  char *t_pool = NULL;
  char *t_name = NULL;
  char *t_snap = NULL;

  char *origin = strdup(cfgstring);
  if (!origin)
    goto failed;
  p = origin;
  sep = strchr(p, '/');
  if (sep) {
    *sep = '\0';
    t_pool = strdup(p);
    p = sep + 1;
  } else {
    t_pool = "rbd";
  } 
  sep = strchr(p, '@');
  if (sep) {
    sep = '\0';
    t_snap = strdup(sep + 1);
  } else {
    t_snap = "";
  }
  t_name = strdup(p);
  if (!strlen(t_name))
    goto failed;
  free(origin);
  *pool = t_pool;
  *name = t_name;
  *snap = t_snap;

  return 0;
  
failed:
  if (t_pool)
    free(t_pool);
  if (t_name)
    free(t_name);
  if (t_snap)
    free(t_snap);
  if (origin)
    free(origin);
  return -1;
}

/*
 *  check connection to cluster named with cluster_name
 *  cluster_name: the name of cluster, default to cluster
 *  conf: the path of ceph config file, default to /etc/ceph/ceph.conf
 *  clientid: client id of cluster, default to admin
 *  key: authentication keyring
 */
static int connect_cluster(rados_t *cluster, char *cluster_name, char *conf, char *clientid, char *key)
{
  char client_full[128];
  int ret = 0;

  if (cluster_name) {
     if (clientid)
       snprintf(client_full, sizeof(client_full),"client.%s",clientid);
     else
       snprintf(client_full, sizeof(client_full),"client.admin");
     ret = rados_create2(cluster, cluster_name, client_full, 0);
  } else {
     ret = rados_create(cluster,clientid);
  }
  if (ret < 0) {
    errp("rados_create error: %d\n", ret);
    goto failed;
  }
  ret = rados_conf_read_file(*cluster, conf);
  if (ret < 0) {
    errp("rados_conf_read_file error: %d\n", ret);
    goto failed;
  }
  if (key) {
    ret = rados_conf_set(*cluster, "key", key);
    if (ret < 0) {
      errp("rados_conf_set set key error: %d\n",key);
      goto failed;
    }
  }
  ret = rados_connect(*cluster);
  if (ret < 0) {
    errp("rados_connect error: %d\n", ret);
    goto failed;
  }
  
failed:
  return ret;
}

/*
static int get_opt_val(char *cfg, char *opt_key, char *conf_key)
{
  int ret = 0;
  int len;
  char *p = strstr(cfg, opt_key);
  if (!p) {
    ret = -1;
    goto failed;
  }
  char *e = strchr(p, ';');
  if (e) {
    len = e - p - strlen(opt_key);
  } else {
    len = strlen(p) - strlen(opt_key);
  }
  conf_key = malloc(len + 1);
  strncpy(conf_key, p + strlen(opt_key), len);
  conf_key[len + 1] = '\0';

failed:
  return ret;
}
*/

/*
 * check rbd config
 * @cfgstring: rbd config string
 * @reason: return value
*/
static bool rbd_check_config(const char *cfgstring, char **reason)
{
  char *rbdname = NULL;
  char *pool = NULL;
  char *name = NULL;
  char *snap = NULL;
  char *conf = NULL;
  char *cluster = NULL;
  char *clientid = NULL;
  char *key = NULL;
  char *path = NULL;
  int ret = 0;
  bool result = true;
  rados_t pcluster = NULL;

  char *oldcfg = strdup(cfgstring);
  
  path = strchr(oldcfg, '/');
  if (!path) {
    if (asprintf(reason, "No path found") == -1) 
      *reason = NULL;
    result = false;
    goto failed;
  }
  rbdname = path + 1;
  /*
  ret = get_opt_val(oldcfg, "rbdname=", rbdname);
  if (ret < 0) {
    if (asprintf(reason, "rbdname not found") == -1)
      *reason = NULL;
    result = false;
    goto failed;
  }
  ret = get_opt_val(oldcfg, "conf=", conf);
  ret = get_opt_val(oldcfg, "cluster=", cluster);
  ret = get_opt_val(oldcfg, "clientid=", clientid);
  ret = get_opt_val(oldcfg, "secretkey=", key);
  */
  ret = parse_imagepath(rbdname, &pool, &name, &snap);
  if (ret < 0) {
    if (asprintf(reason, "cannot parse rbdname") == -1)
      *reason = NULL;
    result = false;
    goto failed;

  }
  ret = connect_cluster(&pcluster, cluster, conf, clientid, key);
  if (ret < 0) {
    if (asprintf(reason, "cannot connect to cluster") == -1)
      *reason = NULL;
    result = false;
    goto failed;
  }
  rados_shutdown(pcluster);
  free(oldcfg);

failed:
  //if (rbdname)
  //  free(rbdname);
  if (conf)
    free(conf);
  if (cluster)
    free(cluster);
  if (clientid)
    free(clientid);
  if (key);
    free(key);
  return result;
}

/*
 * open RBD image 
 * @device: device to be opened
*/
static int tcmu_rbd_open(struct tcmu_device *device)
{
  char *rbdname = NULL;
  char *conf = NULL;
  char *cluster = NULL;
  char *clientid = NULL;
  char *key = NULL;
  int ret = 0;
  struct rbd_state *rbd_st;
  rbd_image_info_t info;
  int attr;
  
  rbd_st = calloc(1, sizeof(struct rbd_state));
  if (!rbd_st)
    return -ENOMEM;
 
  tcmu_set_dev_private(device, rbd_st);

  attr = tcmu_get_attribute(device, "hw_block_size");
  if (attr == -1) {
    errp("cannot get hw_block_size setting\n");
    goto failed;
  }
  rbd_st->block_size = attr;
  
  char *oldcfg = strdup(tcmu_get_dev_cfgstring(device));
  rbdname = strchr(oldcfg, '/');
  if (!rbdname) {
    errp("no path found");
    goto failed;
  }
  
  rbdname += 1;
  /*
  ret = get_opt_val(oldcfg, "rbdname=", rbdname);
  if (ret < 0) {
    errp("rbdname not found");
    goto failed;
  }
  ret = get_opt_val(oldcfg, "conf=", conf);
  ret = get_opt_val(oldcfg, "cluster=", cluster);
  ret = get_opt_val(oldcfg, "clientid=", clientid);
  ret = get_opt_val(oldcfg, "secretkey=", key);
  */
  ret = parse_imagepath(rbdname, &rbd_st->pool, &rbd_st->name, &rbd_st->snap);
  if (ret < 0) {
    errp("cannot parse rbdname");
    goto failed;

  }

  ret = connect_cluster(&rbd_st->cluster, cluster, conf, clientid, key);
  if (ret < 0) {
    errp("cannot connect to cluster");
    goto failed;
  }

  ret = rados_ioctx_create(rbd_st->cluster, rbd_st->pool, &rbd_st->ioctx);
  if (ret < 0) {
    errp("cannot create ioctx");
    goto failed;
  }
  
  ret = rbd_open(rbd_st->ioctx, rbd_st->name, &rbd_st->rbd_image, rbd_st->snap);
  if (ret < 0) {
    errp("cannot open rbd");
    goto failed;
  }

  ret = rbd_stat(rbd_st->rbd_image, &info, sizeof(info));
  if (ret < 0) {
    errp("open rbd error");
    goto failed;
  }
  
//  rbd_st->block_size = info.obj_size;

  return 0;
failed:
  //if (rbdname)
  //  free(rbdname);
  if (conf)
    free(conf);
  if (cluster)
    free(cluster);
  if (clientid)
    free(clientid);
  if (key);
    free(key);
  if (rbd_st->pool)
    free(rbd_st->pool);
  if (rbd_st->name)
    free(rbd_st->name);
  if (rbd_st->snap)
    free(rbd_st->snap);
  free(rbd_st);
  return -EIO;
}

/*
 * close RBD image
 * @device: device to be closed
 */
static void tcmu_rbd_close(struct tcmu_device *device)
{
  struct rbd_state *rbd_st = tcmu_get_dev_private(device);
  if (rbd_st) {
    rbd_close(rbd_st->rbd_image);
    rados_ioctx_destroy(rbd_st->ioctx);
    rados_shutdown(rbd_st->cluster);
  } 
  free(rbd_st);
}

static int set_medium_error(uint8_t *sense)
{
  return tcmu_set_sense_data(sense, MEDIUM_ERROR, ASC_READ_ERROR, NULL);
}

/* 
 * Return scsi status or TCMU_NOT_HANDLED
 * @device: device to be processed
 * @cmd: command issued to device
*/
static int tcmu_rbd_handle_cmd(struct tcmu_device *device, struct tcmulib_cmd *tcmulib_cmd)
{
  uint64_t off, *off1;
  uint32_t len, *len1;
  long long size;
  uint8_t *cdb = tcmulib_cmd->cdb;
  struct iovec *iov = tcmulib_cmd->iovec;
  size_t iov_cnt = tcmulib_cmd->iov_cnt;
  uint8_t *sense = tcmulib_cmd->sense_buf;
  struct rbd_state *rbd_st = tcmu_get_dev_private(device);
  uint8_t cmd;
 
  rbd_image_t rbd_image = rbd_st->rbd_image;
  int ret = 0;
  uint32_t length;
  int result = SAM_STAT_GOOD;
  char *tmpbuf, *writebuf;
  uint64_t offset = rbd_st->block_size * tcmu_get_lba(cdb);
  uint32_t tl = rbd_st->block_size * tcmu_get_xfer_length(cdb);
  int do_verify = 0;
  uint32_t cmp_offset;
  
  dbgp("io start %x %u %llu\n", cdb[0], tl, (unsigned long long)offset);
  cmd = cdb[0];
  switch(cmd) {
    case INQUIRY:
      return tcmu_emulate_inquiry(device, cdb, iov, iov_cnt, sense);
      break;
    case TEST_UNIT_READY:
      return tcmu_emulate_test_unit_ready(cdb, iov, iov_cnt, sense);
      break;
    case SERVICE_ACTION_IN_16:
      if (cdb[1] == READ_CAPACITY_16) {
	long long size;
        unsigned long long num_lbas;

	size = tcmu_get_device_size(device);
	if (size == -1) {
	  errp("Could not get device size\n");
	  return TCMU_NOT_HANDLED;
	}

	num_lbas = size / rbd_st->block_size;

	return tcmu_emulate_read_capacity_16(num_lbas, rbd_st->block_size,
					     cdb, iov, iov_cnt, sense);
      } else {
        return TCMU_NOT_HANDLED;
      }
      break;
    case MODE_SENSE:
    case MODE_SENSE_10:
      return tcmu_emulate_mode_sense(cdb, iov, iov_cnt, sense);
      break;
    case MODE_SELECT:
    case MODE_SELECT_10:
      return tcmu_emulate_mode_select(cdb, iov, iov_cnt, sense);
      break;
    case COMPARE_AND_WRITE:
      /* Blocks are transferred twice, first the set that
       * we compare to the existing data, and second the set
       * to write if the compare was successful.
       */
      length = tl / 2;
      
      tmpbuf = malloc(length);
      if (!tmpbuf) {
        result = tcmu_set_sense_data(sense, HARDWARE_ERROR,
                                    ASC_INTERNAL_TARGET_FAILURE, NULL);
       break;
      } 

      ret = rbd_read(rbd_image, offset, length, tmpbuf);
      if (ret != length) {
        result = set_medium_error(sense);
        free(tmpbuf);
        break;
      }
      cmp_offset = tcmu_compare_with_iovec(tmpbuf, iov, length);
      if (cmp_offset != -1) {
        result = tcmu_set_sense_data(sense, MISCOMPARE,
                                     ASC_MISCOMPARE_DURING_VERIFY_OPERATION,
                                     &cmp_offset);
        free(tmpbuf);
        break;
      }
      
      free(tmpbuf);
 
      tcmu_seek_in_iovec(iov, length);
      goto write;
    case SYNCHRONIZE_CACHE:
    case SYNCHRONIZE_CACHE_16:
      if (cdb[1] & 0x02)
        result = tcmu_set_sense_data(sense, ILLEGAL_REQUEST, 
                                     ASC_INVALID_FIELD_IN_CDB, NULL);
      else {
        int r = rbd_flush(rbd_image);
        if (r)
          set_medium_error(sense);
      }
      break;
    case WRITE_VERIFY:
    case WRITE_VERIFY_12:
    case WRITE_VERIFY_16:
      do_verify = 1;
    case WRITE_6:
    case WRITE_10:
    case WRITE_12:
    case WRITE_16:
      length = tl;  
write:
      writebuf = malloc(length);
      if (!writebuf) {
        result = tcmu_set_sense_data(sense, HARDWARE_ERROR,
                                     ASC_INTERNAL_TARGET_FAILURE, NULL);
        break;
      }

      tcmu_memcpy_from_iovec(writebuf, length, iov, iov_cnt);
      
      ret = rbd_write(rbd_image, offset, length, writebuf);
      if (ret == length) {
        if ((cmd != WRITE_6) && (cdb[1] & 0x8)) {
          int r = rbd_flush(rbd_image);
          if (r)
            set_medium_error(sense);
        }
      } else {
        errp("Error on write %x %x\n", ret, length);
	result = set_medium_error(sense);
	break;
      } 

      free(writebuf);
      if (do_verify)
        goto verify;

      break;
    case WRITE_SAME:
    case WRITE_SAME_16:
      /*
       * WRITE_SAME is default to support since LBPWS/LBPWS10 is set 1
       */ 
      /* WRITE_SAME used to punch hole in file */
      length = tcmu_iovec_length(iov, iov_cnt);

      tmpbuf = malloc(length);

      if (cdb[1] & 0x08) {
        ret = rbd_discard(rbd_image, offset, tl);
        if (ret != 0) {
          result = tcmu_set_sense_data(sense, HARDWARE_ERROR,
                                       ASC_INTERNAL_TARGET_FAILURE, NULL);
        }
        break;
      }
      while (tl > 0) {
        size_t blocksize = rbd_st->block_size;
        uint32_t val32;
	uint64_t val64;
        
        assert(iov->iov_len >= 8);

        switch (cdb[1] & 0x06) {
          case 0x02: 
            /* PBDATA==0 LBDATA==1 */
            val32 = htobe32(offset);
            memcpy(iov->iov_base, &val32, 4);
            break;
          case 0x04: 
            /* PBDATA==1 LBDATA==0 */
            val64 = htobe64(offset);
            memcpy(iov->iov_base, &val64, 8);
            break;
          default:
            errp("PBDATA and LBDATA set!!!\n");
        }

        ret = rbd_write(rbd_image, offset, blocksize, tmpbuf);

        if (ret != blocksize) {
          result = set_medium_error(sense);
          free(tmpbuf);
          break;
        }
        offset += blocksize;
        tl -= blocksize;
      }
      free(tmpbuf);
      break;
    case READ_6:
    case READ_10:
    case READ_12:
    case READ_16:
      length = tcmu_iovec_length(iov, iov_cnt);

      tmpbuf = malloc(length);
      if (!tmpbuf) {
        result = tcmu_set_sense_data(sense, HARDWARE_ERROR,
                                     ASC_INTERNAL_TARGET_FAILURE, NULL);
        break;
      }

      ret = rbd_read(rbd_image, offset, length, tmpbuf);
      if (ret != length) {
        result = set_medium_error(sense);
        errp("Error on read %x %x\n", ret, length);
        free(tmpbuf);
        break;
      }
      ret = tcmu_memcpy_into_iovec(iov, iov_cnt, tmpbuf, length);
      free(tmpbuf);
      break;
    case VERIFY:
    case VERIFY_12:
    case VERIFY_16:
verify:
      length = tcmu_iovec_length(iov, iov_cnt);

      tmpbuf = malloc(length);
      if (!tmpbuf) {
        result = tcmu_set_sense_data(sense, HARDWARE_ERROR,
                                     ASC_INTERNAL_TARGET_FAILURE, NULL);
        break;
      }

      ret = rbd_read(rbd_image, offset, length, tmpbuf);
      if (ret != length) {
        result = set_medium_error(sense);
        errp("Error on read %x %x\n", ret, length);
        free(tmpbuf);
        break;
      }
     
      cmp_offset = tcmu_compare_with_iovec(tmpbuf, iov, length);
      if (cmp_offset != -1) {
        result = tcmu_set_sense_data(sense, MISCOMPARE,
                                     ASC_MISCOMPARE_DURING_VERIFY_OPERATION,
				     &cmp_offset);
      }

      free(tmpbuf);
      break;
    case UNMAP:

      length = tcmu_iovec_length(iov, iov_cnt);
      tmpbuf = malloc(length);
      size = tcmu_get_device_size(device);
       
      /* if ARCHOR bit is set to 1 and ANC_SUP bit in the logical block
       * provisioning VPD page is set to 0 
       */ 
      if (!(cdb[1] & 0x01)) {
        result = tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
                                     ASC_INVALID_FIELD_IN_CDB, NULL);
        break;
      }

      tcmu_memcpy_from_iovec(tmpbuf, length, iov, iov_cnt);

      length -= 8;
      tmpbuf += 8;
      
      while(length > 16) {
        off1 = (uint64_t *)(&tmpbuf[0]);
        off = be64toh(*off1);
        len1 = (uint32_t *)(&tmpbuf[8]);
        len = be32toh(*len1);
  
        if (off + len > size) {
          result = tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
                                       ASC_LBA_OUT_OF_RANGE, NULL);
          break;
        }
        if (len > 0) {
          ret = rbd_discard(rbd_image, off, len);
          if (ret != 0) {
            result = tcmu_set_sense_data(sense, HARDWARE_ERROR,
                                         ASC_INTERNAL_TARGET_FAILURE, NULL);
            break;
          }
        }
        
        length -= 16;
        tmpbuf += 16;
      }       
      break;
    default:
      result = TCMU_NOT_HANDLED;
      break;
  }
  dbgp("io done %p %x %d %u %llu\n", cdb, cmd, result, length,(unsigned long long)offset);

  if (result == TCMU_NOT_HANDLED)
    dbgp("io not handled %p %x %x %d %d %llu\n",
         cdb, result, cmd, ret, length, (unsigned long long)offset);
  else if (result != SAM_STAT_GOOD) {
    errp("io error %p %x %x %d %d %llu\n",
         cdb, result, cmd, ret, length, (unsigned long long)offset);
  }

  return result;
}
static const char rbd_cfg_desc[] = 
  "rbd config string if of the form:\n"
  "\"pool/name@snap\"\n"
  "where:\n"
  "  pool:       The RBD pool name\n"
  "  name:       The RBD name\n"
  "  snap:       The RBD snapshot name\n";

struct tcmur_handler rbd_handler = {
    .name = "Ceph RBD handler",
    .subtype = "rbd",
    .cfg_desc = rbd_cfg_desc,

    .check_config = rbd_check_config,

    .open = tcmu_rbd_open,
    .close = tcmu_rbd_close,
    .handle_cmd = tcmu_rbd_handle_cmd,
};

// Entry point must be named "handler_init"
void handler_init()
{
  tcmur_register_handler(&rbd_handler);
}
